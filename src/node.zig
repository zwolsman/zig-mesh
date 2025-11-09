const std = @import("std");

const zio = @import("zio");

const ID = struct {
    public_key: [32]u8,
    address: ?zio.net.Address,
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
    peer_store: PeerStore,

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

        self.id.address = server.socket.address;

        log.info("Listening on {f}", .{self.id});

        while (true) {
            if (shutdown.load(.acquire)) {
                try self.close();
                break;
            }

            const stream = try server.accept(rt);
            errdefer stream.close(rt);

            log.info("Peer connected: {f}", .{stream.socket.address});
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
        defer {
            peer.close();
            self.allocator.destroy(peer);
        }

        log.debug("Peer accepted: {f}", .{peer.id});

        try self.peer_store.register(peer);
        defer self.peer_store.remove(peer) catch {};

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
            .address = stream.socket.address,
        };
    }

    fn close(self: *Peer) void {
        self.stream.close(self.rt);
        log.info("Closed peer: {f}", .{self.stream.socket.address.ip});
    }
};

const PeerStore = struct {
    const log = std.log.scoped(.peer_store);
    address_peer: std.HashMap(zio.net.Address, *Peer, Context, std.hash_map.default_max_load_percentage),
    key_peer: std.AutoHashMap([32]u8, *Peer),

    const Context = struct {
        pub fn hash(_: @This(), address: zio.net.Address) u64 {
            var hasher = std.hash.Wyhash.init(0);

            switch (address.any.family) {
                std.posix.AF.INET => {
                    hasher.update(std.mem.asBytes(&address.ip.in.addr));
                    hasher.update(std.mem.asBytes(&address.ip.in.port));
                },
                std.posix.AF.INET6 => {
                    hasher.update(std.mem.asBytes(&address.ip.in6.addr));
                    hasher.update(std.mem.asBytes(&address.ip.in6.flowinfo));
                    hasher.update(std.mem.asBytes(&address.ip.in6.scope_id));
                    hasher.update(std.mem.asBytes(&address.ip.in6.port));
                },
                else => unreachable,
            }
            return hasher.final();
        }

        pub fn eql(_: @This(), a: zio.net.Address, b: zio.net.Address) bool {
            if (a.any.family != b.any.family)
                return false;

            return a.toStd().eql(b.toStd());
        }
    };

    pub fn init(allocator: std.mem.Allocator) !PeerStore {
        return .{
            .address_peer = .init(allocator),
            .key_peer = .init(allocator),
        };
    }

    pub fn register(self: *PeerStore, peer: *Peer) !void {
        if (peer.id.address) |addr| {
            try self.address_peer.putNoClobber(addr, peer);
        }

        try self.key_peer.putNoClobber(peer.id.public_key, peer);

        log.debug("Registered peer {f}", .{peer.id});
    }

    pub fn remove(self: *PeerStore, peer: *Peer) !void {
        if (peer.id.address) |addr| {
            _ = self.address_peer.remove(addr);
        }
        _ = self.key_peer.remove(peer.id.public_key);

        log.debug("Removed peer {f}", .{peer.id});
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
        .peer_store = try .init(allocator),
    };
}
