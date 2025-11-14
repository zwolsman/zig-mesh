const std = @import("std");

const zio = @import("zio");

const net = @import("./net.zig");
const Node = @import("./node.zig").Node;
const Peer = @import("./node.zig").Peer;
const Packet = @import("./packet.zig");

const log = std.log.scoped(.tty);

const Tokens = std.mem.TokenIterator(u8, .scalar);

pub fn run(allocator: std.mem.Allocator, rt: *zio.Runtime, node: *Node) !void {
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
            handleConnect(allocator, rt, node, &tokens) catch |err| {
                log.warn("Could not handle connect command: {}", .{err});
            };
        } else if (std.mem.eql(u8, upper_cmd, "ECHO")) {
            handleEcho(allocator, rt, node, &tokens) catch |err| {
                log.warn("Could not handle echo command: {}", .{err});
            };
        } else if (std.mem.eql(u8, upper_cmd, "PING")) {
            handlePing(allocator, rt, node, &tokens) catch |err| {
                log.warn("Could not handle ping command: {}", .{err});
            };
        } else {
            std.debug.print("Unknown command: {s}\n", .{upper_cmd});
        }
    }
}

fn handleConnect(
    allocator: std.mem.Allocator,
    rt: *zio.Runtime,
    node: *Node,
    tokens: *Tokens,
) !void {
    _ = allocator;
    const raw_address = tokens.rest();
    const addr = try net.parseIpAddress(raw_address);

    const peer = try node.getOrCreatePeer(rt, addr) orelse {
        return error.PeerNotFound;
    };

    std.debug.print("Connected to peer {f}\n", .{peer.id});
}

fn handleEcho(
    allocator: std.mem.Allocator,
    rt: *zio.Runtime,
    node: *Node,
    tokens: *Tokens,
) !void {
    _ = rt;
    const dest_id = try parsePeerId(tokens);

    const peer = node.peer_store.key_peer.get(dest_id) orelse {
        log.warn("Not connected to {x}", .{dest_id});
        return error.PeerNotFound;
    };

    log.debug("Found peer: {f}.. writing", .{peer.id});

    const msg = try allocator.dupe(u8, tokens.rest());
    defer allocator.free(msg);

    _ = try Packet.writePacket(&peer.conn.writer, .command, .{ .echo = .{ .message = msg } });
    try peer.conn.output.flush();

    log.debug("Echo sent: {s}!", .{msg});
}

fn handlePing(
    allocator: std.mem.Allocator,
    rt: *zio.Runtime,
    node: *Node,
    tokens: *Tokens,
) !void {
    _ = allocator;
    const dest_id = try parsePeerId(tokens);

    const peer = node.peer_store.key_peer.get(dest_id) orelse {
        log.warn("Not connected to {x}", .{dest_id});
        return error.PeerNotFound;
    };

    log.debug("Found peer: {f}.. writing", .{peer.id});
    const req_id = (try Packet.writePacket(&peer.conn.writer, .request, .ping)).?;
    try peer.conn.output.flush();

    log.debug("Ping sent (id={x})!", .{req_id});

    // TODO: add time-out handling
    var resp_task = try rt.spawn(Peer.receiveResponse, .{ peer, rt, req_id }, .{});
    defer resp_task.cancel(rt);
    const resp_id: Packet.ID, const resp: Packet.Tag = try resp_task.join(rt);

    if (resp != .ping) {
        log.debug("Unexpected op: {}", .{resp});
    } else {
        log.debug("Received ping response (id={x})", .{&resp_id});
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
