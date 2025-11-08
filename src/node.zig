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
    clients: std.AutoHashMap(ID, *Client),
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

            log.info("Client connected: {f}", .{stream.socket.address.ip});
            var task = try rt.spawn(handleClient, .{ self, rt, stream }, .{});
            task.detach(rt);
        }
    }

    fn close(self: *Self) !void {
        _ = self; // autofix
        log.info("Shutting down gracefully...", .{});
    }

    fn handleClient(self: *Self, rt: *zio.Runtime, stream: zio.net.Stream) !void {
        errdefer stream.close(rt);

        const clientId = Client.handshake(rt, stream, self.id) catch |err| switch (err) {
            error.HandshakeFailed => return,
            else => return err,
        };

        var client = Client{ .rt = rt, .stream = stream, .id = clientId };

        defer client.close();
        log.debug("Client accepted: {f}", .{client.id});

        try client.run();
    }
};

const Client = struct {
    const log = std.log.scoped(.client);
    rt: *zio.Runtime,
    stream: zio.net.Stream,
    id: ID,
    pub const Error = error{HandshakeFailed};

    fn run(self: *Client) !void {
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

        var client_pubkey: [32]u8 = undefined;
        const key = try reader.interface.takeArray(32);
        @memcpy(&client_pubkey, key);

        var write_buffer: [1024]u8 = undefined;
        var writer = stream.writer(rt, &write_buffer);

        try writer.interface.print("hello{f}", .{id});
        try writer.interface.flush();

        return .{
            .public_key = client_pubkey,
            .address = stream.socket.address.ip,
        };
    }

    fn close(self: *Client) void {
        self.stream.close(self.rt);
        log.info("Closed client: {f}", .{self.stream.socket.address.ip});
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
        .clients = .init(allocator),
    };
}
