const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;
const X25519 = std.crypto.dh.X25519;

const zio = @import("zio");

const kademlia = @import("kademlia.zig");
const noise = @import("noise.zig");
const protocol = @import("protocol.zig");

pub const Identity = union(enum) {
    pub const PublicKey = [Ed25519.PublicKey.encoded_length]u8;

    full: Ed25519.KeyPair,
    public: Ed25519.PublicKey,

    pub fn generate() Identity {
        return .{
            .full = .generate(),
        };
    }

    pub fn generateDeterministic(seed: [Ed25519.seed_length]u8) !Identity {
        return .{
            .full = try .generateDeterministic(seed),
        };
    }

    pub fn initPublic(bytes: [32]u8) !Identity {
        return .{
            .public = try Ed25519.PublicKey.fromBytes(bytes),
        };
    }

    pub fn sign(self: *const Identity, msg: []const u8) ![Ed25519.Signature.encoded_length]u8 {
        switch (self.*) {
            .full => |kp| {
                const sig = try kp.sign(msg, null);

                return sig.toBytes();
            },
            else => return error.MissingSecretKey,
        }
    }

    pub fn verify(self: *const Identity, sig_bytes: [Ed25519.Signature.encoded_length]u8, msg: []const u8) !void {
        const public_key = switch (self.*) {
            .full => |kp| kp.public_key,
            .public => |public_key| public_key,
        };

        const sig = Ed25519.Signature.fromBytes(sig_bytes);
        try sig.verify(msg, public_key);
    }

    pub fn publicKey(self: *const Identity) PublicKey {
        const public_key = switch (self.*) {
            .full => |kp| kp.public_key,
            .public => |public_key| public_key,
        };

        return public_key.toBytes();
    }
};

const HandshakeResult = struct {
    identity: Identity,
    send: noise.CipherState,
    recv: noise.CipherState,
};

pub const Node = struct {
    const Self = @This();
    const log = std.log.scoped(.node);

    allocator: std.mem.Allocator,
    rt: *zio.Runtime,
    identity: Identity,

    connections: std.AutoHashMap(Identity.PublicKey, *Connection),
    connections_mutex: std.Thread.Mutex = .{},

    transport: TCPTransport,
    event_handler: CompositePeerEventHandler,

    accept_task: ?zio.JoinHandle(void) = null,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    pub fn init(allocator: std.mem.Allocator, rt: *zio.Runtime, identity: Identity) !Self {
        return .{
            .allocator = allocator,
            .rt = rt,

            .identity = identity,
            .event_handler = .init(allocator),

            .connections = .init(allocator),
            .transport = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        self.shutdown();

        // Clean up all connections
        self.connections_mutex.lock();
        defer self.connections_mutex.unlock();

        var it = self.connections.valueIterator();
        while (it.next()) |conn_ptr| {
            conn_ptr.*.deinit();
        }
        self.connections.deinit();

        self.transport.close(self.rt);
        self.event_handler.deinit();
    }

    /// Start listening for incoming connections
    pub fn start(self: *Self, listen_address: std.net.Address) !void {
        try self.transport.listen(self.rt, listen_address);
        self.running.store(true, .seq_cst);

        log.debug("started listening on {f}", .{self.transport.server.?.socket.address});

        // Start accept loop in background task
        self.accept_task = try self.rt.spawn(acceptLoop, .{self}, .{});
        self.accept_task.?.detach(self.rt);
    }

    /// Shutdown the node
    pub fn shutdown(self: *Self) void {
        self.running.store(false, .seq_cst);

        if (self.accept_task) |*task| {
            task.cancel(self.rt);
        }
    }

    /// Get or connect to remote peer
    pub fn connect(self: *Self, address: std.net.Address) !*Connection {
        const stream = try self.transport.connect(self.rt, address);
        errdefer stream.close(self.rt);

        const handshake_result = try self.handshake(stream, .initiator);

        // Create connection
        const conn = try Connection.init(self.allocator, self.rt, stream, handshake_result);
        errdefer conn.deinit();

        // Store connection
        self.connections_mutex.lock();
        defer self.connections_mutex.unlock();

        try self.connections.put(conn.id.publicKey(), conn);

        // Trigger event
        self.event_handler.interface.onPeerConnected(conn);

        // Start receive loop for this connection
        conn.receive_task = try self.rt.spawn(receiveLoop, .{ self, conn }, .{});

        return conn;
    }

    /// Send message to remote peer
    pub fn sendMessage(self: *Self, destination: Identity, op: protocol.WriteOp, tag: protocol.Payload) !void {
        const conn = self.connections.get(destination.publicKey()) orelse return error.UnknownPeer;

        _ = try conn.sendMessage(op, tag);
    }

    /// Accept loop (runs in background task)
    fn acceptLoop(self: *Self) void {
        while (self.running.load(.seq_cst)) {
            const connection = self.transport.accept(self.rt) catch |err| {
                if (err == error.NotListening) break;
                self.event_handler.interface.onError(err);
                continue;
            };

            self.handleIncomingConnection(connection) catch |err| {
                self.event_handler.interface.onError(err);
                connection.close(self.rt);
            };
        }
    }

    fn handleIncomingConnection(self: *Self, stream: zio.net.Stream) !void {
        const handshake_result = try self.handshake(stream, .responder);
        const conn = try Connection.init(self.allocator, self.rt, stream, handshake_result);

        self.connections_mutex.lock();
        defer self.connections_mutex.unlock();

        try self.connections.put(handshake_result.identity.publicKey(), conn);

        // Trigger event
        self.event_handler.interface.onPeerConnected(conn);

        // Start receive loop for this connection
        conn.receive_task = try self.rt.spawn(receiveLoop, .{ self, conn }, .{});
        conn.receive_task.?.detach(self.rt);
    }

    fn handshake(self: *Self, stream: zio.net.Stream, role: noise.Role) !HandshakeResult {
        // Allocate buffers for handshake
        var tcp_recv_buffer: [4096]u8 = undefined;
        var tcp_send_buffer: [4096]u8 = undefined;

        var encoder_buffer: [512]u8 = undefined;
        var decoder_buffer: [512]u8 = undefined;

        var tcp_reader = stream.reader(self.rt, &tcp_recv_buffer);
        var decoder = protocol.Decoder.init(&tcp_reader.interface, .empty, &decoder_buffer);

        var tcp_writer = stream.writer(self.rt, &tcp_send_buffer);
        var encoder = protocol.Encoder.init(&tcp_writer.interface, .empty, &encoder_buffer);

        const NOISE_PROTOCOL_NAME = "Noise_XX_25519_ChaChaPoly_SHA256";

        var state = try noise.HandshakeState.init(self.allocator, NOISE_PROTOCOL_NAME, role, null, null, .{
            .s = .generate(),
        });
        defer state.deinit();

        switch (role) {
            .responder => {
                // Stage 1
                _ = try state.read(&decoder.reader);
                log.debug("Stage 1 (ok)", .{});

                // Stage 2
                const payload: [96]u8 = self.identity.publicKey() ++ try self.identity.sign(&state.s.public_key);
                _ = try state.write(&encoder.writer, &payload);
                try encoder.writer.flush();
                try tcp_writer.interface.flush();

                log.debug("Stage 2 (ok)", .{});

                // Stage 3
                const remote_payload, const chains = try state.read(&decoder.reader);
                if (remote_payload.len != 96) {
                    return error.HandshakeFailed;
                }

                if (chains == null) {
                    return error.HandshakeFailed;
                }

                const identity = try Identity.initPublic(remote_payload[0..32].*);
                try identity.verify(remote_payload[32..96].*, &state.rs.?);

                log.debug("Stage 3 (ok)", .{});
                log.debug("handshake hash: {x}", .{state.handshakeHash()});

                return .{
                    .identity = identity,
                    .send = chains.?[1],
                    .recv = chains.?[0],
                };
            },
            .initiator => {
                // Stage 1
                _ = try state.write(&encoder.writer, &.{});
                try encoder.writer.flush();
                try tcp_writer.interface.flush();

                log.debug("Stage 1 (ok)", .{});

                // Stage 2
                const remote_payload, _ = try state.read(&decoder.reader);
                if (remote_payload.len != 96) {
                    return error.HandshakeFailed;
                }

                const identity = try Identity.initPublic(remote_payload[0..32].*);
                try identity.verify(remote_payload[32..96].*, &state.rs.?);

                log.debug("Stage 2 (ok)", .{});

                // Stage 3
                const payload = self.identity.publicKey() ++ try self.identity.sign(&state.s.public_key);
                const chains = try state.write(&encoder.writer, &payload);
                if (chains == null) {
                    return error.HandshakeFailed;
                }
                try encoder.writer.flush();
                try tcp_writer.interface.flush();

                log.debug("Stage 3 (ok)", .{});
                log.debug("handshake hash: {x}", .{state.handshakeHash()});

                return .{
                    .identity = identity,
                    .send = chains.?[0],
                    .recv = chains.?[1],
                };
            },
        }
    }

    fn receiveLoop(self: *Self, conn: *Connection) void {
        while (conn.state == .connected) {
            const op, const payload = conn.receiveMessage() catch |err| {
                self.event_handler.interface.onError(err);
                break;
            };

            log.debug("op: {any}, payload: {any}", .{ op, payload });

            // Handle special message types
            if (op == .command and payload == .echo) {
                std.debug.print("{x}: {s}\n", .{ &conn.id.publicKey(), payload.echo.message });
            } else {
                self.event_handler.interface.onMessageReceived(
                    conn.id.publicKey(),
                    op,
                    payload,
                );
            }
        }

        // Connection closed, clean up
        self.disconnect(conn.id.publicKey());
    }

    /// Disconnect from a specific peer
    pub fn disconnect(self: *Node, peer_id: [32]u8) void {
        self.connections_mutex.lock();
        defer self.connections_mutex.unlock();

        if (self.connections.fetchRemove(peer_id)) |entry| {
            self.event_handler.interface.onPeerDisconnected(peer_id);
            entry.value.deinit();
        }
    }
};

const TCPTransport = struct {
    const Self = @This();

    const backlog = 128;
    server: ?zio.net.Server = null,

    pub fn listen(self: *Self, rt: *zio.Runtime, address: std.net.Address) !void {
        const addr = zio.net.Address.fromStd(address);

        self.server = try addr.ip.listen(rt, .{
            .kernel_backlog = backlog,
            .reuse_address = true,
        });
    }

    pub fn accept(self: *Self, rt: *zio.Runtime) !zio.net.Stream {
        const server = self.server orelse return error.NotListening;

        return server.accept(rt);
    }

    pub fn connect(self: *Self, rt: *zio.Runtime, address: std.net.Address) !zio.net.Stream {
        _ = self;
        const addr = zio.net.Address.fromStd(address);

        return try addr.connect(rt);
    }

    pub fn close(self: *Self, rt: *zio.Runtime) void {
        if (self.server) |*server| {
            server.close(rt);
        }
    }
};

const ConnectionState = enum { connecting, connected, closing, closed };

pub const Connection = struct {
    allocator: std.mem.Allocator,
    rt: *zio.Runtime,

    id: Identity,
    stream: zio.net.Stream,

    // I/O buffers - these are owned by PeerConnection
    tcp_recv_buffer: []u8,
    tcp_send_buffer: []u8,

    enc_buffer: []u8,
    dec_buffer: []u8,

    reader: zio.net.Stream.Reader,
    writer: zio.net.Stream.Writer,

    // Encoder/Decoder
    encoder: protocol.Encoder,
    decoder: protocol.Decoder,

    state: ConnectionState,
    receive_task: ?zio.JoinHandle(void) = null,

    /// Initialize a PeerConnection after successful handshake
    pub fn init(
        allocator: std.mem.Allocator,
        rt: *zio.Runtime,
        stream: zio.net.Stream,
        handshake_result: HandshakeResult,
    ) !*Connection {
        const conn = try allocator.create(Connection);
        errdefer allocator.destroy(conn);

        // Allocate I/O buffers
        const tcp_recv_buffer = try allocator.alloc(u8, 1028);
        errdefer allocator.free(tcp_recv_buffer);

        const tcp_send_buffer = try allocator.alloc(u8, 1028);
        errdefer allocator.free(tcp_send_buffer);

        const encoder_buffer = try allocator.alloc(u8, 1028);
        errdefer allocator.free(encoder_buffer);

        const decoder_buffer = try allocator.alloc(u8, 1028);
        errdefer allocator.free(decoder_buffer);

        conn.* = .{
            .allocator = allocator,
            .rt = rt,
            .id = handshake_result.identity,
            .stream = stream,

            .tcp_recv_buffer = tcp_recv_buffer,
            .tcp_send_buffer = tcp_send_buffer,

            .enc_buffer = encoder_buffer,
            .dec_buffer = decoder_buffer,

            .writer = stream.writer(rt, tcp_send_buffer),
            .reader = stream.reader(rt, tcp_recv_buffer),

            .encoder = protocol.Encoder.init(&conn.writer.interface, handshake_result.send, encoder_buffer),
            .decoder = protocol.Decoder.init(&conn.reader.interface, handshake_result.recv, decoder_buffer),

            .state = .connected,
        };

        return conn;
    }

    pub fn deinit(self: *Connection) void {
        self.state = .closed;

        if (self.receive_task) |*task| {
            task.cancel(self.rt);
        }

        self.stream.close(self.rt);
        self.allocator.free(self.tcp_recv_buffer);
        self.allocator.free(self.tcp_send_buffer);
        self.allocator.free(self.enc_buffer);
        self.allocator.free(self.dec_buffer);
        self.allocator.destroy(self);
    }

    /// Send a message to this peer
    pub fn sendMessage(
        self: *Connection,
        op: protocol.WriteOp,
        tag: protocol.Payload,
    ) !void {
        if (self.state != .connected) {
            return error.NotConnected;
        }

        _ = try self.encoder.write(op, tag);
        try self.writer.interface.flush();
    }

    /// Receive the next message from this peer
    pub fn receiveMessage(self: *Connection) !struct { protocol.Op, protocol.Payload } {
        if (self.state != .connected) {
            return error.NotConnected;
        }

        return try self.decoder.read();
    }

    pub fn close(self: *Connection) void {
        self.state = .closing;
        // self.encoder.writeMessage(.close, "") catch {};
        self.state = .closed;
    }
};

const RelayedConnection = struct {
    const protocol_name = "Noise_IK_25519_ChaChaPoly_SHA256";
    const log = std.log.scoped(.relayed_conn);

    const Self = @This();

    allocator: std.mem.Allocator,
    hop_identity: Identity,
    encoder_buffer: []u8,
    decoder_buffer: []u8,

    handshake_state: noise.HandshakeState,

    send_cipher: ?noise.CipherState = null,
    recv_cipher: ?noise.CipherState = null,

    write_mutex: std.Thread.Mutex = .{},
    read_mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, hop_identity: Identity, destination: Identity) !*Self {
        const conn = try allocator.create(RelayedConnection);
        errdefer allocator.destroy(conn);
        const role: noise.Role = switch (destination) {
            .full => .responder,
            .public => .initiator,
        };

        conn.* = .{
            .allocator = allocator,
            .hop_identity = hop_identity,
            .encoder_buffer = try allocator.alloc(u8, 1028),
            .decoder_buffer = try allocator.alloc(u8, 1028),
            .handshake_state = try .init(allocator, protocol_name, role, null, null, .{
                .rs = if (destination == .public) try X25519.publicKeyFromEd25519(destination.public) else null,
                .s = if (destination == .full) try X25519.KeyPair.fromEd25519(destination.full) else null,
            }),
        };

        return conn;
    }

    pub fn deinit(self: *Self) void {
        self.handshake_state.deinit();

        self.allocator.free(self.encoder_buffer);
        self.allocator.free(self.decoder_buffer);
        self.allocator.destroy(self);
    }

    pub fn sendMessage(self: *Self, destination: Identity, conn: *Connection, op: protocol.WriteOp, tag: protocol.Payload) !void {
        self.write_mutex.lock();
        defer self.write_mutex.unlock();
        var writer = std.Io.Writer.fixed(self.encoder_buffer);

        const payload = if (self.send_cipher) |*c| payload: {
            log.debug("already has encoder", .{});

            _ = try protocol.writeMessage(&writer, op, tag);

            break :payload try c.encryptWithAd(self.encoder_buffer, "", writer.buffered());
        } else payload: {
            log.debug("using handshake state -- {s} ({s})", .{ protocol_name, @tagName(self.handshake_state.role) });

            // Create payload
            _ = try protocol.writeMessage(&writer, op, tag);

            const end = writer.end;

            // Write handshake message
            const ciphers = try self.handshake_state.write(&writer, writer.buffered());

            if (ciphers) |c| {
                log.debug("Finalised IK handshake ({s})", .{@tagName(self.handshake_state.role)});
                switch (self.handshake_state.role) {
                    .initiator => {
                        self.send_cipher = c.@"0";
                        self.recv_cipher = c.@"1";
                    },
                    .responder => {
                        self.send_cipher = c.@"1";
                        self.recv_cipher = c.@"0";
                    },
                }
            }

            break :payload writer.buffer[end..writer.end];
        };

        log.debug("route payload: {any}", .{payload});

        var route: protocol.Payload.Route = undefined;
        route.destination = destination.publicKey();
        route.hops_buff[0] = self.hop_identity.publicKey();
        route.hops_len = 1;
        route.payload = payload;

        // Create route command
        try conn.sendMessage(.command, .{ .route = route });
    }

    pub fn readMessage(self: *Self, in: *std.Io.Reader) !struct { protocol.Op, protocol.Payload } {
        self.read_mutex.lock();
        defer self.read_mutex.unlock();

        const payload = if (self.recv_cipher) |*c| p: {
            log.debug("already has decoder", .{});

            break :p try c.decryptWithAd(self.decoder_buffer, "", in.buffered());
        } else p: {
            const payload, const ciphers = try self.handshake_state.read(in);

            if (ciphers) |c| {
                log.debug("Finalised IK handshake ({s})", .{@tagName(self.handshake_state.role)});

                switch (self.handshake_state.role) {
                    .initiator => {
                        self.send_cipher = c.@"0";
                        self.recv_cipher = c.@"1";
                    },
                    .responder => {
                        self.send_cipher = c.@"1";
                        self.recv_cipher = c.@"0";
                    },
                }
            }

            break :p payload;
        };

        var reader = std.Io.Reader.fixed(payload);
        return protocol.readMessage(&reader);
    }
};

pub const RoutingNode = struct {
    const Self = @This();
    const log = std.log.scoped(.router);

    base: *Node,
    allocator: std.mem.Allocator,
    routing_table: kademlia.RoutingTable,
    routing_mutex: std.Thread.Mutex = .{},

    // Track relayed connections (E2E encrypted)
    relayed_connections: std.AutoHashMap(Identity.PublicKey, *RelayedConnection),
    relayed_mutex: std.Thread.Mutex = .{},

    event_handler: PeerEventHandler = .{
        .onPeerConnectedFn = onPeerConnected,
        .onPeerDisconnectedFn = onPeerDisconnected,
        .onMessageReceivedFn = onMessageReceived,
    },

    pub fn init(allocator: std.mem.Allocator, node: *Node) Self {
        return .{
            .allocator = allocator,
            .base = node,
            .routing_table = .{
                .public_key = node.identity.publicKey(),
            },
            .relayed_connections = .init(allocator),
        };
    }

    /// start routing support by registering the event handler
    pub fn start(self: *Self) !void {
        try self.base.event_handler.register(&self.event_handler);
    }

    pub fn sendMessage(self: *Self, destination: Identity, op: protocol.WriteOp, tag: protocol.Payload) !void {
        self.base.sendMessage(destination, op, tag) catch |err| {
            return switch (err) {
                error.UnknownPeer => self.forwardMessage(destination, op, tag),
                else => err,
            };
        };
    }

    fn forwardMessage(self: *Self, destination: Identity, op: protocol.WriteOp, tag: protocol.Payload) !void {
        self.relayed_mutex.lock();
        defer self.relayed_mutex.unlock();

        const result = try self.relayed_connections.getOrPut(destination.publicKey());
        if (!result.found_existing) {
            result.value_ptr.* = try RelayedConnection.init(self.allocator, self.base.identity, destination);
        }

        const relayed_conn = result.value_ptr.*;

        var peers: [16]*Connection = undefined;
        const len = self.routing_table.closestTo(&peers, destination.publicKey());
        if (len == 0) return error.Unroutable;

        for (peers[0..len]) |conn| {
            relayed_conn.sendMessage(destination, conn, op, tag) catch |err| {
                log.debug("Could not forward route to: {x}: {}", .{ &conn.id.publicKey(), err });
                continue;
            };

            return;
        }

        return error.Unroutable;
    }

    fn onPeerConnected(h: *PeerEventHandler, conn: *Connection) void {
        const self: *Self = @alignCast(@fieldParentPtr("event_handler", h));
        self.routing_mutex.lock();
        defer self.routing_mutex.unlock();

        const result = self.routing_table.put(conn);

        log.debug("routing table route {x} ({s})", .{ &conn.id.publicKey(), @tagName(result) });
    }

    fn onPeerDisconnected(h: *PeerEventHandler, peer_id: Identity.PublicKey) void {
        const self: *Self = @alignCast(@fieldParentPtr("event_handler", h));
        self.routing_mutex.lock();
        defer self.routing_mutex.unlock();

        if (self.routing_table.delete(peer_id)) {
            log.debug("routing table route {x} (removed)", .{&peer_id});
        }
    }

    fn onMessageReceived(h: *PeerEventHandler, peer_id: Identity.PublicKey, op: protocol.Op, tag: protocol.Payload) void {
        if (op != .command) return;
        if (tag != .route) return;
        const self: *Self = @alignCast(@fieldParentPtr("event_handler", h));

        self.handleRoute(peer_id, tag.route) catch |err| {
            log.debug("Could not handle route from {x}: {}", .{ &peer_id, err });
        };
    }

    fn handleRoute(self: *Self, peer_id: Identity.PublicKey, route: protocol.Payload.Route) !void {
        log.debug("Received route command from {x}", .{&peer_id});
        log.debug("payload len={d}, data={any}", .{ route.payload.len, route.payload });
        log.debug("hops ({d}): ", .{route.hops_len});
        for (route.hops()) |h| {
            log.debug("\t - {x}", .{&h});
        }

        if (std.mem.eql(u8, &route.destination, &self.base.identity.publicKey())) {
            log.debug("End station received", .{});
            return self.processRoutedMessage(route);
        }

        var updated_route = route;
        updated_route.hops_buff[route.hops_len] = self.base.identity.publicKey();
        updated_route.hops_len += 1;

        const result = self.base.sendMessage(try .initPublic(route.destination), .command, .{ .route = updated_route });

        if (result != error.UnknownPeer) {
            return result;
        }

        var peers: [16]*Connection = undefined;
        const len = self.routing_table.closestTo(&peers, route.destination);
        if (len == 0) return error.Unroutable;
        log.debug("Found {d} peers to route to", .{len});
        for (0..len) |i| {
            log.debug("\t- {x}", .{&peers[i].id.publicKey()});
        }

        hop: for (peers[0..len]) |conn| {
            if (std.mem.eql(u8, &conn.id.publicKey(), &peer_id))
                continue :hop;

            for (route.hops()) |hop| {
                // potential hop is already used
                if (std.mem.eql(u8, &hop, &conn.id.publicKey()))
                    continue :hop;
            }

            conn.sendMessage(.command, .{ .route = updated_route }) catch |err| {
                log.debug("Could not forward route to {x}: {}", .{ &conn.id.publicKey(), err });
                continue;
            };
            log.debug("Forward route to {x}", .{&conn.id.publicKey()});
            return;
        }
    }

    fn processRoutedMessage(self: *Self, route: protocol.Payload.Route) !void {
        self.relayed_mutex.lock();
        defer self.relayed_mutex.unlock();

        const result = try self.relayed_connections.getOrPut(route.hops_buff[0]); // TODO: fix this
        if (!result.found_existing) {
            result.value_ptr.* = try RelayedConnection.init(self.allocator, self.base.identity, self.base.identity);
        }

        const relayed_conn = result.value_ptr.*;
        var in = std.Io.Reader.fixed(route.payload);

        const op, const payload = try relayed_conn.readMessage(&in);

        log.debug("routed message: {s}, {any}", .{ @tagName(op), payload });
        self.base.event_handler.interface.onMessageReceived(route.hops_buff[0], op, payload);
    }

    pub fn deinit(self: *Self) void {
        self.relayed_mutex.lock();
        defer self.relayed_mutex.unlock();
        var it = self.relayed_connections.valueIterator();
        while (it.next()) |conn| {
            conn.*.deinit();
        }
        self.relayed_connections.deinit();
    }
};

pub const PeerEventHandler = struct {
    const Self = @This();

    onPeerConnectedFn: ?*const fn (*Self, *Connection) void = null,
    onPeerDisconnectedFn: ?*const fn (*Self, Identity.PublicKey) void = null,
    onMessageReceivedFn: ?*const fn (*Self, Identity.PublicKey, protocol.Op, protocol.Payload) void = null,
    onErrorFn: ?*const fn (*Self, anyerror) void = null,

    pub fn onPeerConnected(self: *Self, connection: *Connection) void {
        if (self.onPeerConnectedFn) |callback| {
            callback(self, connection);
        }
    }

    pub fn onPeerDisconnected(self: *Self, peer_id: Identity.PublicKey) void {
        if (self.onPeerDisconnectedFn) |callback| {
            callback(self, peer_id);
        }
    }

    pub fn onMessageReceived(self: *Self, peer_id: Identity.PublicKey, op: protocol.Op, payload: protocol.Payload) void {
        if (self.onMessageReceivedFn) |callback| {
            callback(self, peer_id, op, payload);
        }
    }

    pub fn onError(self: *Self, err: anyerror) void {
        if (self.onErrorFn) |callback| {
            callback(self, err);
        }
    }
};

const CompositePeerEventHandler = struct {
    const Self = @This();

    interface: PeerEventHandler,
    handlers: std.array_list.Managed(*PeerEventHandler),

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .handlers = .init(allocator),
            .interface = .{
                .onPeerConnectedFn = onPeerConnected,
                .onMessageReceivedFn = onMessageReceived,
                .onPeerDisconnectedFn = onPeerDisconnected,
                .onErrorFn = onError,
            },
        };
    }

    pub fn register(self: *Self, handler: *PeerEventHandler) !void {
        try self.handlers.append(handler);
    }

    pub fn deinit(self: *Self) void {
        self.handlers.deinit();
    }

    fn onPeerConnected(h: *PeerEventHandler, conn: *Connection) void {
        const self: *Self = @alignCast(@fieldParentPtr("interface", h));
        for (self.handlers.items) |handler| {
            handler.onPeerConnected(conn);
        }
    }

    fn onMessageReceived(h: *PeerEventHandler, peer_id: Identity.PublicKey, op: protocol.Op, payload: protocol.Payload) void {
        const self: *Self = @alignCast(@fieldParentPtr("interface", h));
        for (self.handlers.items) |handler| {
            handler.onMessageReceived(peer_id, op, payload);
        }
    }

    fn onPeerDisconnected(h: *PeerEventHandler, peer_id: Identity.PublicKey) void {
        const self: *Self = @alignCast(@fieldParentPtr("interface", h));
        for (self.handlers.items) |handler| {
            handler.onPeerDisconnected(peer_id);
        }
    }

    fn onError(h: *PeerEventHandler, err: anyerror) void {
        const self: *Self = @alignCast(@fieldParentPtr("interface", h));
        for (self.handlers.items) |handler| {
            handler.onError(err);
        }
    }
};
