const std = @import("std");

const zio = @import("zio");

const ID = struct {
    public_key: [32]u8,
    address: ?zio.net.IpAddress,
    pub fn format(self: ID, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        if (self.address) |addr| {
            try std.Io.Writer.print(writer, "{f}[{x}]", .{ addr, &self.public_key });
        } else {
            try std.Io.Writer.print(writer, "[{x}]", .{&self.public_key});
        }
    }
};

const Node = struct {
    const Self = @This();
    const log = std.log.scoped(.node);

    allocator: std.mem.Allocator,
    id: ID,

    pub fn runUntilComplete(node: *Node, rt: *zio.Runtime) !void {
        var shutdown = std.atomic.Value(bool).init(false);

        // Spawn server task
        var server_task = try rt.spawn(Node.serverLoop, .{ node, rt, &shutdown, 0 }, .{});
        defer server_task.cancel(rt);

        // Spawn signal handler task
        var signal_task = try rt.spawn(signalHandler, .{ rt, &shutdown }, .{});
        defer signal_task.cancel(rt);

        try rt.run();
    }

    fn signalHandler(rt: *zio.Runtime, shutdown: *std.atomic.Value(bool)) !void {
        var sig = try zio.Signal.init(.interrupt);
        defer sig.deinit();

        try sig.wait(rt);

        std.log.info("Received signal, initiating shutdown...", .{});
        shutdown.store(true, .release);
    }

    fn serverLoop(self: *Self, rt: *zio.Runtime, shutdown: *std.atomic.Value(bool), port: u16) !void {
        const addr = try zio.net.IpAddress.parseIp4("127.0.0.1", port);

        const server = try addr.listen(rt, .{});
        defer server.close(rt);

        self.id.address = server.socket.address.ip;

        log.info("Listening on {f}", .{self.id});

        while (true) {
            if (shutdown.load(.acquire)) {
                try self.close();
                break;
            }

            const stream = try server.accept(rt);
            errdefer stream.close(rt);

            log.info("Peer connected: {f}", .{stream.socket.address.ip});
            var task = try rt.spawn(handlePeer, .{ self, rt, stream }, .{});
            task.detach(rt);
        }
    }

    fn close(self: *Self) !void {
        _ = self; // autofix
        log.info("Shutting down gracefully...", .{});
    }

    fn handlePeer(self: *Self, rt: *zio.Runtime, stream: zio.net.Stream) !void {
        errdefer stream.close(rt);

        const peerId = Peer.handshake(rt, stream, self.id) catch |err| switch (err) {
            error.HandshakeFailed => return,
            else => return err,
        };

        const peer = try Peer.init(self.allocator, rt, stream, peerId);
        defer peer.close();

        log.debug("Peer accepted: {f}", .{peer.id});
        try peer.run();
    }
};

const Peer = struct {
    const log = std.log.scoped(.peer);
    rt: *zio.Runtime,
    stream: zio.net.Stream,
    id: ID,
    pub const Error = error{HandshakeFailed};

    pub fn init(allocator: std.mem.Allocator, rt: *zio.Runtime, stream: zio.net.Stream, id: ID) !*Peer {
        const peer = try allocator.create(Peer);

        peer.* = .{
            .rt = rt,
            .id = id,
            .stream = stream,
        };

        return peer;
    }

    fn run(self: *Peer) !void {
        var read_buffer: [1024]u8 = undefined;
        var reader = self.stream.reader(self.rt, &read_buffer);

        var write_buffer: [1024]u8 = undefined;
        var writer = self.stream.writer(self.rt, &write_buffer);

        while (true) {
            const line = reader.interface.takeDelimiterInclusive('\n') catch |err| switch (err) {
                error.EndOfStream => break,
                else => return err,
            };
            try writer.interface.writeAll(line);
            try writer.interface.flush();
        }
    }

    fn handshake(rt: *zio.Runtime, stream: zio.net.Stream, id: ID) !ID {
        var read_buffer: [1024]u8 = undefined;
        var reader = stream.reader(rt, &read_buffer);
        const line = try reader.interface.takeDelimiterExclusive('\n');
        if (!std.mem.eql(u8, line, "hey!")) {
            log.debug("Handshake failed, disconnecting", .{});
            return Error.HandshakeFailed;
        }

        var peer_pubkey: [32]u8 = undefined;
        const key = try reader.interface.takeArray(32);
        @memcpy(&peer_pubkey, key);

        var write_buffer: [1024]u8 = undefined;
        var writer = stream.writer(rt, &write_buffer);

        try writer.interface.print("hello{f}", .{id});
        try writer.interface.flush();

        return .{
            .public_key = peer_pubkey,
            .address = stream.socket.address.ip,
        };
    }

    fn close(self: *Peer) void {
        self.stream.close(self.rt);
        log.info("Closed peer: {f}", .{self.stream.socket.address.ip});
    }
};

const Options = struct {
    kp: std.crypto.sign.Ed25519.KeyPair,
};

pub fn init(allocator: std.mem.Allocator, kp: std.crypto.sign.Ed25519.KeyPair) !Node {
    return .{
        .allocator = allocator,
        .id = .{
            .public_key = kp.public_key.toBytes(),
            .address = null,
        },
    };
}
