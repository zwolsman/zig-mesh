const std = @import("std");

const flags = @import("flags");
const zio = @import("zio");

const Node = @import("./node.zig").Node;
const Packet = @import("./packet.zig");

const Flags = struct {
    seed: ?u256 = null,
    listen_address: ?[]const u8 = null,
    interactive: bool = false,
    positional: struct {
        trailing: []const []const u8,
    },

    pub const switches = .{
        .listen_address = 'l',
        .interactive = 'i',
    };

    pub fn parseIpAddress(address: []const u8) !std.net.Address {
        const parsed = splitHostPort(address) catch |err| return switch (err) {
            error.DelimiterNotFound => std.net.Address.parseIp("127.0.0.1", try std.fmt.parseUnsigned(u16, address, 10)),
            else => err,
        };

        const parsed_host = parsed.host;
        const parsed_port = try std.fmt.parseUnsigned(u16, parsed.port, 10);
        if (parsed_host.len == 0) return std.net.Address.parseIp("0.0.0.0", parsed_port);

        return std.net.Address.parseIp(parsed_host, parsed_port);
    }

    const HostPort = struct {
        host: []const u8,
        port: []const u8,
    };

    fn splitHostPort(address: []const u8) !HostPort {
        var j: usize = 0;
        var k: usize = 0;

        const i = std.mem.lastIndexOfScalar(u8, address, ':') orelse return error.DelimiterNotFound;

        const host = parse: {
            if (address[0] == '[') {
                const end = std.mem.indexOfScalar(u8, address, ']') orelse return error.MissingEndBracket;
                if (end + 1 == i) {} else if (end + 1 == address.len) {
                    return error.MissingRightBracket;
                } else {
                    return error.MissingPort;
                }

                j = 1;
                k = end + 1;
                break :parse address[1..end];
            }

            if (std.mem.indexOfScalar(u8, address[0..i], ':') != null) {
                return error.TooManyColons;
            }
            break :parse address[0..i];
        };

        if (std.mem.indexOfScalar(u8, address[j..], '[') != null) {
            return error.UnexpectedLeftBracket;
        }
        if (std.mem.indexOfScalar(u8, address[k..], ']') != null) {
            return error.UnexpectedRightBracket;
        }

        const port = address[i + 1 ..];

        return HostPort{ .host = host, .port = port };
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    const rt = try zio.Runtime.init(allocator, .{ .thread_pool = .{ .enabled = true } });
    defer rt.deinit();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    const options = flags.parse(args, "node", Flags, .{});

    const address = try if (options.listen_address) |raw_address|
        Flags.parseIpAddress(raw_address)
    else
        std.net.Address.parseIp4("127.0.0.1", 0);

    const kp = if (options.seed) |seed|
        try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(std.mem.toBytes(seed))
    else
        std.crypto.sign.Ed25519.KeyPair.generate();

    const seed = std.mem.bytesToValue(u256, &kp.secret_key.seed());
    std.log.debug("seed: {d}", .{seed});

    var node = try Node.init(allocator, kp);
    defer node.deinit();

    try node.bind(rt, address);

    var node_job = try rt.spawn(Node.run, .{ &node, rt }, .{});
    node_job.detach(rt);

    var bootstrap_job = try rt.spawn(bootstrapNode, .{ rt, &node, options.positional.trailing }, .{});
    bootstrap_job.detach(rt);

    if (options.interactive) {
        var tty_job = try rt.spawn(tty, .{ allocator, rt, &node }, .{});
        tty_job.detach(rt);
    }

    try rt.run();
}

fn bootstrapNode(rt: *zio.Runtime, node: *Node, bootstrap_addresses: []const []const u8) void {
    if (bootstrap_addresses.len == 0) return;

    for (bootstrap_addresses) |raw_address| {
        const addr = Flags.parseIpAddress(raw_address) catch |err| {
            std.log.debug("Could not parse {s}: {}", .{ raw_address, err });
            continue;
        };

        const peer = node.getOrCreatePeer(rt, addr) catch |err| {
            std.log.debug("Could not connect to peer {f}: {}", .{ addr, err });
            continue;
        } orelse {
            std.log.debug("Could not find peer {f}", .{addr});
            continue;
        };

        std.log.debug("Connected to bootstrap peer {f}", .{peer.id});
        // TODO: query bootstrap peer for their peers
    }

    std.log.debug("Finished bootstrapping", .{});
}

fn tty(allocator: std.mem.Allocator, rt: *zio.Runtime, node: *Node) !void {
    const log = std.log.scoped(.tty);
    log.debug("Waiting for command..", .{});
    var in = zio.Pipe.init(std.fs.File.stdin());

    var buffer: [1024]u8 = undefined;
    var reader = in.reader(rt, &buffer);
    while (true) {
        const raw_command = try reader.interface.takeDelimiterExclusive('\n');
        var tokens = std.mem.tokenizeScalar(u8, raw_command, ' ');

        var upper_buf: [32]u8 = undefined;
        if (tokens.peek()) |name| {
            if (name.len > upper_buf.len) {
                log.err("command name too long", .{});
                continue;
            }
        } else {
            continue;
        }

        const upper_cmd = std.ascii.upperString(&upper_buf, tokens.next().?);
        if (std.mem.eql(u8, upper_cmd, "HELP")) {
            std.debug.print("There is no help, figure it out yoruself\n", .{});
        } else if (std.mem.eql(u8, upper_cmd, "PEERS")) {
            std.debug.print("{} peer(s) connected\n", .{node.peer_store.address_peer.count()});
            var it = node.peer_store.address_peer.valueIterator();
            while (it.next()) |peer| {
                std.debug.print("  {f}\n", .{peer.*.id});
            }
        } else if (std.mem.eql(u8, upper_cmd, "ID")) {
            std.debug.print("{f}\n", .{node.id});
        } else if (std.mem.eql(u8, upper_cmd, "CONNECT")) {
            const raw_address = tokens.rest();
            const addr = Flags.parseIpAddress(raw_address) catch |err| {
                log.err("Could not parse address {s}: {}", .{ raw_address, err });
                continue;
            };

            const peer = node.getOrCreatePeer(rt, addr) catch |err| {
                log.warn("Could not connect to peer {f}: {}", .{ addr, err });
                continue;
            } orelse {
                log.warn("Could not connect to peer {f}", .{addr});
                continue;
            };

            std.debug.print("Connected to peer {f}\n", .{peer.id});
        } else if (std.mem.eql(u8, upper_cmd, "ECHO")) {
            const dest_id = try parsePeerId(&tokens);

            const peer = node.peer_store.key_peer.get(dest_id) orelse {
                log.warn("Not connected to {x}", .{dest_id});
                continue;
            };

            log.debug("Found peer: {f}.. writing", .{peer.id});

            const msg = try allocator.dupe(u8, tokens.rest());
            defer allocator.free(msg);

            const payload = Packet.Echo{ .msg = msg };

            try Packet.writePacket(&peer.conn.writer, .command, .echo, payload);
            try peer.conn.output.flush();

            log.debug("Echo sent: {s}!", .{payload.msg});
        } else if (std.mem.eql(u8, upper_cmd, "PING")) {
            const dest_id = try parsePeerId(&tokens);

            const peer = node.peer_store.key_peer.get(dest_id) orelse {
                log.warn("Not connected to {x}", .{dest_id});
                continue;
            };

            log.debug("Found peer: {f}.. writing", .{peer.id});
            try Packet.writePacket(&peer.conn.writer, .command, .ping, null);
            try peer.conn.output.flush();

            log.debug("Ping sent!", .{});
        } else {
            std.debug.print("Unknown command: {s}\n", .{upper_cmd});
        }
    }
}

fn parsePeerId(it: *std.mem.TokenIterator(u8, .scalar)) ![32]u8 {
    const raw_dest_id = it.next() orelse {
        return error.MissingPeerId;
    };

    if (raw_dest_id.len != 64) {
        std.log.warn("Destination id not 64 chars", .{});
        return error.PeerIdLengthMismatch;
    }

    var peer_id: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&peer_id, raw_dest_id);
    return peer_id;
}
