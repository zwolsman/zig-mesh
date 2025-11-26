const std = @import("std");

const zio = @import("zio");

const kamdelia = @import("kademlia.zig");
const net = @import("net.zig");
const noise = @import("noise.zig");
const Packet = @import("packet.zig");

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
    routing_table: kamdelia.RoutingTable,
    server: ?zio.net.Server,
    kp: std.crypto.sign.Ed25519.KeyPair,

    pub fn init(allocator: std.mem.Allocator, kp: std.crypto.sign.Ed25519.KeyPair) !Node {
        return .{
            .allocator = allocator,
            .kp = kp,
            .id = .{
                .public_key = kp.public_key.toBytes(),
                .address = null,
            },
            .routing_table = .{
                .public_key = kp.public_key.toBytes(),
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
        // self.id.address = server.socket.address;
        self.server = server;

        log.info("Listening on {f}{f}", .{ server.socket.address, self.id });
    }

    pub fn run(node: *Node, rt: *zio.Runtime) !void {
        // Spawn server task
        var server_task = try rt.spawn(Node.serverLoop, .{ node, rt }, .{});
        server_task.detach(rt);
    }

    pub fn getOrCreatePeer(node: *Node, rt: *zio.Runtime, address: std.net.Address) !?*Peer {
        const addr = zio.net.Address.fromStd(address);

        if (node.peer_store.address_peer.get(addr)) |peer| {
            log.debug("Already connected to peer {f}: {f}", .{ addr, peer.id });
            return peer;
        } else {
            log.debug("Trying to connect to peer: {f}", .{addr});

            // TODO: why doesn't the normal method not work --> const stream = try addr.connect(rt);
            const stream = try zio.net.tcpConnectToHost(rt, "localhost", addr.ip.getPort());

            const peer = try node.acceptPeer(rt, stream, .initiator);
            log.debug("Connected to peer: {f}", .{addr});

            return peer;
        }
    }

    fn serverLoop(self: *Self, rt: *zio.Runtime) !void {
        const server = self.server orelse return error.NoServer;

        while (true) {
            const stream = try server.accept(rt);
            errdefer stream.close(rt);

            log.info("Peer connected: {f}", .{stream.socket.address});
            _ = self.acceptPeer(rt, stream, .responder) catch |err| {
                log.warn("Could not accept peer: {}", .{err});
                continue;
            };
        }
    }

    pub fn shutdown(self: *Self, rt: *zio.Runtime) void {
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

    fn acceptPeer(self: *Self, rt: *zio.Runtime, stream: zio.net.Stream, role: HandshakeRole) !*Peer {
        const handshake = try Peer.handshake(self.allocator, rt, stream, self.kp, role);

        const peer = Peer.init(try self.allocator.create(Peer), rt, stream, .{
            .public_key = handshake.public_key,
            .address = handshake.address,
        }, .{
            .recv = handshake.recv,
            .write = handshake.send,
        });
        log.debug("Peer handshake: {f} (ok)", .{peer.id});

        var peer_job = try rt.spawn(peerLoop, .{ self, rt, peer }, .{});
        peer_job.detach(rt);

        return peer;
    }

    fn peerLoop(self: *Self, rt: *zio.Runtime, peer: *Peer) !void {
        _ = rt; // autofix
        self.peer_store.register(peer) catch |err| {
            log.warn("Could not register peer {f}: {} -- diconnecting", .{ peer.id, err });
            peer.close();
            return err;
        };

        switch (self.routing_table.put(.{ .public_key = peer.id.public_key, .address = peer.stream.socket.address })) {
            .full => log.info("Peer {x} registered (full)", .{&peer.id.public_key}),
            .updated => log.info("Peer {x} registered (updated)", .{&peer.id.public_key}),
            .inserted => log.info("Peer {x} registered (inserted)", .{&peer.id.public_key}),
        }

        defer peer.close();
        defer self.peer_store.remove(peer) catch unreachable;
        defer _ = self.routing_table.delete(peer.id.public_key);

        while (true) {
            const op, const tag = Packet.readPacket(&peer.conn.reader) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return err,
            };
            log.debug("Received packet {}({})", .{ op, tag });

            self.nodePacketHandler(peer, op, tag) catch |err| {
                log.warn("Could not handle packet {}({}): {}", .{ op, tag, err });
                continue;
            };
        }

        log.debug("Stopped listening {f}", .{self.id});
    }

    fn nodePacketHandler(node: *Node, peer: *Peer, op: Packet.Op, tag: Packet.Tag) !void {
        switch (op) {
            .command => switch (tag) {
                .echo => |payload| {
                    log.debug("{f}: {s}", .{ peer.id, payload.message });
                },
                .route => |route| {
                    if (std.mem.eql(u8, &node.id.public_key, &route.destination)) {
                        log.debug("Received routed packet: {any}", .{route});
                    } else {
                        log.debug("Having to forward packet: {}", .{route});
                    }
                },
                else => return error.UnexpectedOp,
            },
            .request => switch (tag) {
                .ping => {
                    log.debug("{f}: ping", .{peer.id});

                    _ = try Packet.writePacket(&peer.conn.writer, .{ .response = op.request }, .ping);
                    try peer.conn.flush();
                },
                else => return error.UnexpectedOp,
            },
            .response => |request_id| {
                try peer.responses.send(.{ request_id, tag });
            },
        }
    }
};

const HandshakeRole = enum { initiator, responder };
pub const Peer = struct {
    const log = std.log.scoped(.peer);
    const ResponseChannel = zio.BroadcastChannel(struct { Packet.ID, Packet.Tag });

    rt: *zio.Runtime,
    stream: zio.net.Stream,
    id: ID,

    tcp_read_buffer: [1024]u8,
    tcp_write_buffer: [1024]u8,

    conn_read_buffer: [1024]u8,
    conn_write_buffer: [1024]u8,

    reader: zio.net.Stream.Reader,
    writer: zio.net.Stream.Writer,

    responses_buffer: [16]struct { Packet.ID, Packet.Tag },
    responses: ResponseChannel,

    conn: ConnectionClient,

    pub const Error = error{HandshakeFailed};

    pub fn init(peer: *Peer, rt: *zio.Runtime, stream: zio.net.Stream, id: ID, ciphers: struct { recv: noise.CipherState, write: noise.CipherState }) *Peer {
        peer.* = .{
            .rt = rt,
            .id = id,
            .stream = stream,

            .responses_buffer = undefined,

            .tcp_read_buffer = undefined,
            .tcp_write_buffer = undefined,

            .conn_read_buffer = undefined,
            .conn_write_buffer = undefined,

            .reader = stream.reader(rt, &peer.tcp_read_buffer),
            .writer = stream.writer(rt, &peer.tcp_write_buffer),

            .conn = ConnectionClient.initWithCiphers(&peer.reader.interface, &peer.writer.interface, &peer.conn_read_buffer, &peer.conn_write_buffer, ciphers.recv, ciphers.write),
            .responses = ResponseChannel.init(&peer.responses_buffer),
        };

        return peer;
    }

    const NOISE_PROTOCOL_NAME = "Noise_XX_25519_ChaChaPoly_SHA256";

    fn handshake(allocator: std.mem.Allocator, rt: *zio.Runtime, stream: zio.net.Stream, kp: std.crypto.sign.Ed25519.KeyPair, role: HandshakeRole) !struct {
        public_key: [32]u8,
        address: zio.net.Address,
        send: noise.CipherState,
        recv: noise.CipherState,
    } {
        var tcp_read_buffer: [512]u8 = undefined;
        var tcp_reader = stream.reader(rt, &tcp_read_buffer);

        var tcp_write_buffer: [512]u8 = undefined;
        var tcp_writer = stream.writer(rt, &tcp_write_buffer);

        var conn_read_buffer: [512]u8 = undefined;
        var conn_write_buffer: [512]u8 = undefined;

        var conn: ConnectionClient = .init(&tcp_reader.interface, &tcp_writer.interface, &conn_read_buffer, &conn_write_buffer);

        log.debug("Starting handshake ({s} - {})", .{ NOISE_PROTOCOL_NAME, role });

        if (role == .initiator) {
            var state = try noise.HandshakeState.init(allocator, NOISE_PROTOCOL_NAME, .initiator, null, null, .{
                .s = .generate(),
            });
            defer state.deinit();

            // Stage 1
            _ = try state.write(&conn.writer, &.{});
            try conn.flush();
            log.debug("Stage 1 (ok)", .{});

            // Stage 2
            const remote_payload, _ = try state.read(&conn.reader);
            if (remote_payload.len != std.crypto.sign.Ed25519.PublicKey.encoded_length + std.crypto.sign.Ed25519.Signature.encoded_length) {
                return error.HandshakeFailed;
            }

            const raw_pub = remote_payload[0..std.crypto.sign.Ed25519.PublicKey.encoded_length];
            const remote_pub = try std.crypto.sign.Ed25519.PublicKey.fromBytes(raw_pub.*);
            const raw_sig = remote_payload[std.crypto.sign.Ed25519.PublicKey.encoded_length .. std.crypto.sign.Ed25519.PublicKey.encoded_length + std.crypto.sign.Ed25519.Signature.encoded_length];
            const remote_sig = std.crypto.sign.Ed25519.Signature.fromBytes(raw_sig.*);
            try remote_sig.verify(&state.rs.?, remote_pub);

            log.debug("Stage 2 pub: {x}..{x}, sig: {x}..{x} (ok)", .{ raw_pub[0..8], raw_pub[raw_pub.len - 8 ..], raw_sig[0..8], raw_sig[raw_sig.len - 8 ..] });

            // Stage 3
            const payload = kp.public_key.bytes ++ (try kp.sign(&state.s.public_key, null)).toBytes();
            const chains = try state.write(&conn.writer, &payload);
            if (chains == null) {
                return error.HandshakeFailed;
            }
            try conn.writer.flush();
            try tcp_writer.interface.flush();

            log.debug("Stage 3 payload: {x}..{x} (ok)", .{ payload[0..8], payload[payload.len - 8 ..] });
            log.debug("handshake hash: {x}", .{state.handshakeHash()});

            return .{
                .public_key = remote_pub.bytes,
                .address = stream.socket.address,
                .send = chains.?[0],
                .recv = chains.?[1],
            };
        } else {
            var state = try noise.HandshakeState.init(allocator, NOISE_PROTOCOL_NAME, .responder, null, null, .{
                .s = .generate(),
            });
            defer state.deinit();

            // Stage 1
            _ = try state.read(&conn.reader);
            log.debug("Stage 1 (ok)", .{});

            // Stage 2
            const payload: [96]u8 = kp.public_key.bytes ++ (try kp.sign(&state.s.public_key, null)).toBytes();
            _ = try state.write(&conn.writer, &payload);
            try conn.writer.flush();
            try tcp_writer.interface.flush();

            log.debug("Stage 2 payload: {x}..{x} (ok)", .{ payload[0..8], payload[payload.len - 8 ..] });

            // Stage 3
            const remote_payload, const chains = try state.read(&conn.reader);
            if (remote_payload.len != std.crypto.sign.Ed25519.PublicKey.encoded_length + std.crypto.sign.Ed25519.Signature.encoded_length) {
                return error.HandshakeFailed;
            }
            if (chains == null) {
                return error.HandshakeFailed;
            }

            const raw_pub = remote_payload[0..std.crypto.sign.Ed25519.PublicKey.encoded_length];
            const remote_pub = try std.crypto.sign.Ed25519.PublicKey.fromBytes(raw_pub.*);
            const raw_sig = remote_payload[std.crypto.sign.Ed25519.PublicKey.encoded_length .. std.crypto.sign.Ed25519.PublicKey.encoded_length + std.crypto.sign.Ed25519.Signature.encoded_length];
            const remote_sig = std.crypto.sign.Ed25519.Signature.fromBytes(raw_sig.*);
            try remote_sig.verify(&state.rs.?, remote_pub);

            log.debug("Stage 3 pub: {x}..{x}, sig: {x}..{x} (ok)", .{ raw_pub[0..8], raw_pub[raw_pub.len - 8 ..], raw_sig[0..8], raw_sig[raw_sig.len - 8 ..] });
            log.debug("handshake hash: {x}", .{state.handshakeHash()});

            return .{
                .public_key = remote_pub.bytes,
                .address = stream.socket.address,
                .send = chains.?[1],
                .recv = chains.?[0],
            };
        }
    }

    pub fn receiveResponse(peer: *Peer, rt: *zio.Runtime, id: Packet.ID) !struct { Packet.ID, Packet.Tag } {
        var consumer = ResponseChannel.Consumer{};
        peer.responses.subscribe(&consumer);
        defer peer.responses.unsubscribe(&consumer);

        while (peer.responses.receive(rt, &consumer)) |response| {
            const resp_id, _ = response;

            if (std.mem.eql(u8, &id, &resp_id)) {
                return response;
            }
        } else |err| switch (err) {
            // error.Closed => {},
            // error.Lagged => {}, // Fell behind, continue from current position
            else => return err,
        }
    }

    fn close(self: *Peer) void {
        self.stream.close(self.rt);
        log.info("Closed peer: {f}", .{self.id});
    }
};

const PeerStore = struct {
    const log = std.log.scoped(.peer_store);
    address_peer: std.HashMap(zio.net.Address, *Peer, net.AddressContext, std.hash_map.default_max_load_percentage),
    key_peer: std.AutoHashMap([32]u8, *Peer),

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
            log.debug("Registering address: {f}", .{addr});
            try self.address_peer.putNoClobber(addr, peer);
        }

        log.debug("Registering key: {x}", .{&peer.id.public_key});
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

pub const ConnectionClient = struct {
    const log = std.log.scoped(.connection_client);
    const ContentType = enum {
        handshake,
        application_data,
    };

    const MIN_BUFFER_LEN = 256;
    /// The buffer is asserted to have capacity at least `min_buffer_len`.
    input: *std.Io.Reader,
    /// Decrypted stream from the server to the client.
    reader: std.Io.Reader,

    /// The encrypted stream from the client to the server. Bytes are pushed here
    /// via `writer`.
    ///
    /// The buffer is asserted to have capacity at least `min_buffer_len`.
    output: *std.Io.Writer,
    /// The plaintext stream from the client to the server.
    writer: std.Io.Writer,

    write_cipher: ?noise.CipherState = null,
    recv_cipher: ?noise.CipherState = null,
    content_type: ContentType,

    const PACKET_VERSION: u8 = 1;
    pub const header_len = 4; // version(u8) + content type (u8) + len(u16)

    pub fn init(input: *std.Io.Reader, output: *std.Io.Writer, read_buffer: []u8, write_buffer: []u8) ConnectionClient {
        return .{
            .input = input,
            .output = output,
            .content_type = .handshake,
            .reader = .{
                .buffer = read_buffer,
                .vtable = &.{
                    .stream = stream,
                    .readVec = readVec,
                },
                .seek = 0,
                .end = 0,
            },
            .writer = .{
                .buffer = write_buffer,
                .vtable = &.{
                    .drain = drain,
                    .flush = flush_,
                },
            },
        };
    }

    pub fn initWithCiphers(input: *std.Io.Reader, output: *std.Io.Writer, read_buffer: []u8, write_buffer: []u8, recv_cipher: noise.CipherState, write_cipher: noise.CipherState) ConnectionClient {
        var conn = init(input, output, read_buffer, write_buffer);
        conn.recv_cipher = recv_cipher;
        conn.write_cipher = write_cipher;
        conn.content_type = .application_data;

        return conn;
    }

    pub fn flush(self: *ConnectionClient) !void {
        try self.writer.flush();
        try self.output.flush();
    }

    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        // This function writes exclusively to the buffer.
        _ = w;
        _ = limit;
        const c: *ConnectionClient = @alignCast(@fieldParentPtr("reader", r));
        return readIndirect(c);
    }

    fn readVec(r: *std.Io.Reader, data: [][]u8) std.Io.Reader.Error!usize {
        // This function writes exclusively to the buffer.
        _ = data;
        const c: *ConnectionClient = @alignCast(@fieldParentPtr("reader", r));
        return readIndirect(c);
    }

    fn readIndirect(c: *ConnectionClient) std.Io.Reader.Error!usize {
        const r = &c.reader;
        const input = c.input;

        log.debug("input buf: {any}", .{input.buffered()});

        const packet_header = try input.peek(header_len);
        const packet_version = std.mem.readInt(u8, packet_header[0..1], .big);
        const packet_content_type: ContentType = @enumFromInt(std.mem.readInt(u8, packet_header[1..2], .big));
        const packet_size = std.mem.readInt(u16, packet_header[2..4], .big);
        const packet_end: u16 = if (c.recv_cipher != null) packet_size + header_len + 16 else packet_size + header_len;

        log.debug("peeked (version={d}, type={} size={d}, end={d}) {any}", .{ packet_version, packet_content_type, packet_size, packet_end, packet_header });
        log.debug("buffer: {any}", .{input.buffered()});

        if (packet_version != PACKET_VERSION) {
            return error.ReadFailed;
        }

        if (packet_content_type != c.content_type) {
            // TODO: set inner error maybe
            log.debug("Invalid content type (recv={}, excpected={})", .{ packet_content_type, c.content_type });
            return error.ReadFailed;
        }

        log.debug("Received packet of size {d}", .{packet_size});
        if (packet_end > input.bufferedLen()) {
            log.debug("Filling more as packet is not completely buffered: packet end = {d}, buf len = {d}", .{ packet_end, input.bufferedLen() });
            try input.fillMore();

            // Packet not well read; returning 0.
            if (packet_end > input.bufferedLen()) return 0;
        }
        log.debug("prepped buffer: {any}", .{input.buffered()});

        rebase(r, packet_end);
        input.toss(header_len); // already peaked
        const packet_buffer = try input.take(packet_end - header_len); // actual packet

        if (c.recv_cipher != null) {
            _ = c.recv_cipher.?.decryptWithAd(r.buffer[r.end..], "", packet_buffer) catch {
                return error.ReadFailed;
            };
        } else {
            @memcpy(r.buffer[r.end..][0..packet_size], packet_buffer);
        }
        // Should be packet size but it's not wrapped yet
        r.end += packet_size;
        return packet_size;
    }

    fn rebase(r: *std.Io.Reader, capacity: usize) void {
        if (r.buffer.len - r.end >= capacity) return;
        const data = r.buffer[r.seek..r.end];
        @memmove(r.buffer[0..data.len], data);
        r.seek = 0;
        r.end = data.len;
        std.debug.assert(r.buffer.len - r.end >= capacity);
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const c: *ConnectionClient = @alignCast(@fieldParentPtr("writer", w));
        const output = c.output;
        const output_buffer = try output.writableSliceGreedy(MIN_BUFFER_LEN);

        var in_end: usize = 0;
        var buf_end: usize = 0;
        done: {
            {
                const buf = w.buffered();
                const in_len, const buf_len = try c.writePacket(output_buffer[buf_end..], buf);

                buf_end += buf_len;
                in_end += in_len;
                if (in_len < buf.len) break :done;
            }
            for (data[0 .. data.len - 1]) |buf| {
                const in_len, const buf_len = try c.writePacket(output_buffer[buf_end..], buf);

                buf_end += buf_len;
                in_end += in_len;
                if (in_len < buf.len) break :done;
            }
            const buf = data[data.len - 1];
            for (0..splat) |_| {
                const in_len, const buf_len = try c.writePacket(output_buffer[buf_end..], buf);

                buf_end += buf_len;
                in_end += in_len;
                if (in_len < buf.len) break :done;
            }
        }

        output.advance(buf_end);
        return w.consume(in_end);
    }

    fn flush_(w: *std.Io.Writer) std.Io.Writer.Error!void {
        const c: *ConnectionClient = @alignCast(@fieldParentPtr("writer", w));
        const output = c.output;
        const output_buffer = try output.writableSliceGreedy(MIN_BUFFER_LEN);
        const buf = w.buffered();

        _, const buf_len = try c.writePacket(output_buffer, buf);

        log.debug("flushing {any}", .{output_buffer[0..buf_len]});
        output.advance(buf_len);
        w.end = 0;
    }

    fn writePacket(c: *ConnectionClient, output: []u8, data: []const u8) !struct { usize, usize } {
        var writer = std.Io.Writer.fixed(output);
        try writer.writeInt(u8, PACKET_VERSION, .big); // version always set to 1
        try writer.writeInt(u8, @intFromEnum(c.content_type), .big);
        try writer.writeInt(u16, @intCast(data.len), .big);

        if (c.write_cipher != null) {
            const encrypted = c.write_cipher.?.encryptWithAd(writer.unusedCapacitySlice(), "", data) catch {
                return error.WriteFailed;
            };

            writer.advance(encrypted.len);
        } else {
            try writer.writeAll(data);
        }

        return .{
            data.len,
            writer.end,
        };
    }
};
