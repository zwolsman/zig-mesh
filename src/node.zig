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

pub const Node = struct {
    const Self = @This();
    const log = std.log.scoped(.node);

    allocator: std.mem.Allocator,
    id: ID,
    peer_store: PeerStore,
    server: ?zio.net.Server,

    pub fn init(allocator: std.mem.Allocator, kp: std.crypto.sign.Ed25519.KeyPair) !Node {
        return .{
            .allocator = allocator,
            .id = .{
                .public_key = kp.public_key.toBytes(),
                .address = null,
            },
            .peer_store = try .init(allocator),
            .server = null,
        };
    }

    pub fn deinit(self: *Node) void {
        self.peer_store.deinit();
    }

    pub fn bind(self: *Node, rt: *zio.Runtime, address: std.net.Address) !void {
        const addr = zio.net.Address.fromStd(address);
        const server = try addr.ip.listen(rt, .{ .reuse_address = true });

        // TODO: set external ip, not the local ip :)
        self.id.address = server.socket.address;
        self.server = server;

        log.info("Listening on {f}", .{self.id});
    }

    pub fn run(node: *Node, rt: *zio.Runtime) !void {
        // Spawn server task
        var server_task = try rt.spawn(Node.serverLoop, .{ node, rt }, .{});
        server_task.detach(rt);

        // Spawn signal handler task
        var signal_task = try rt.spawn(signalHandler, .{ node, rt }, .{});
        signal_task.detach(rt);
    }

    pub fn getOrCreatePeer(node: *Node, rt: *zio.Runtime, address: std.net.Address) !?*Peer {
        const addr = zio.net.Address.fromStd(address);

        const result = try node.peer_store.address_peer.getOrPut(addr);
        if (!result.found_existing) {
            log.debug("Trying to connect to peer: {f}", .{addr});

            // TODO: why doesn't the normal method not work --> const stream = try addr.connect(rt);
            const stream = try zio.net.tcpConnectToHost(rt, "localhost", addr.ip.getPort());
            log.debug("Connected to peer: {f}", .{addr});

            const peer_id = try Peer.handshake(rt, stream, node.id, .initiator);
            const peer = try Peer.init(node.allocator, rt, stream, peer_id);

            log.debug("Handshake complete for peer {f}", .{peer.id});
            result.value_ptr.* = peer;
        }

        return result.value_ptr.*;
    }

    fn signalHandler(node: *Node, rt: *zio.Runtime) !void {
        var sig = try zio.Signal.init(.interrupt);
        defer sig.deinit();

        try sig.wait(rt);

        std.log.info("Received signal, initiating shutdown...", .{});
        node.shutdown(rt);
    }

    fn serverLoop(self: *Self, rt: *zio.Runtime) !void {
        const server = self.server orelse return error.NoServer;

        while (true) {
            const stream = try server.accept(rt);
            errdefer stream.close(rt);

            log.info("Peer connected: {f}", .{stream.socket.address});
            var task = try rt.spawn(handlePeer, .{ self, rt, stream }, .{});
            task.detach(rt);
        }
    }

    fn shutdown(self: *Self, rt: *zio.Runtime) void {
        log.info("Shutting down gracefully...", .{});

        log.info("Closing peers (n={d})...", .{self.peer_store.address_peer.count()});
        var it = self.peer_store.address_peer.valueIterator();
        while (it.next()) |peer| {
            peer.*.close();
            self.peer_store.remove(peer.*) catch {};
        }

        if (self.server) |server| {
            log.info("Closing server...", .{});
            server.shutdown(rt, .both) catch {};
            server.close(rt);
        }
    }

    fn handlePeer(self: *Self, rt: *zio.Runtime, stream: zio.net.Stream) !void {
        errdefer stream.close(rt);

        const peerId = Peer.handshake(rt, stream, self.id, .responder) catch |err| switch (err) {
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

    fn handshake(rt: *zio.Runtime, stream: zio.net.Stream, id: ID, role: enum { initiator, responder }) !ID {
        var read_buffer: [1024]u8 = undefined;
        var reader = stream.reader(rt, &read_buffer);

        var write_buffer: [1024]u8 = undefined;
        var writer = stream.writer(rt, &write_buffer);

        switch (role) {
            .initiator => {
                try writer.interface.print("hey!\n", .{});
                try writer.interface.flush();
                const line = try reader.interface.takeDelimiterExclusive('\n');
                if (!std.mem.eql(u8, line, "hello!")) {
                    log.debug("Handshake failed, disconnecting", .{});
                    return Error.HandshakeFailed;
                }

                try writer.interface.print("{x}\n", .{id.public_key});
                try writer.interface.flush();

                var peer_pubkey: [32]u8 = undefined;
                const key = try reader.interface.takeArray(32);
                @memcpy(&peer_pubkey, key);

                return .{
                    .public_key = peer_pubkey,
                    .address = stream.socket.address,
                };
            },
            .responder => {
                const line = try reader.interface.takeDelimiterExclusive('\n');
                if (!std.mem.eql(u8, line, "hey!")) {
                    log.debug("Handshake failed, disconnecting", .{});
                    return Error.HandshakeFailed;
                }

                try writer.interface.print("hello!\n", .{});
                try writer.interface.flush();

                var peer_pubkey: [32]u8 = undefined;
                const key = try reader.interface.takeArray(32);
                @memcpy(&peer_pubkey, key);

                try writer.interface.print("{x}\n", .{id.public_key});
                try writer.interface.flush();

                return .{
                    .public_key = peer_pubkey,
                    .address = stream.socket.address,
                };
            },
        }
    }

    fn close(self: *Peer) void {
        self.stream.close(self.rt);
        log.info("Closed peer: {f}", .{self.id});
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

    pub fn deinit(self: *PeerStore) void {
        self.address_peer.deinit();
        self.key_peer.deinit();
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
