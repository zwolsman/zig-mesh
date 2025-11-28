const std = @import("std");

const zio = @import("zio");

const net = @import("net.zig");
const peer = @import("peer.zig");

const log = std.log.scoped(.tty);

const Tokens = std.mem.TokenIterator(u8, .scalar);

pub fn run(allocator: std.mem.Allocator, rt: *zio.Runtime, router: *peer.RoutingNode) !void {
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
            std.debug.print("{} peer(s) connected\n", .{router.base.connections.count()});
            var it = router.base.connections.valueIterator();
            while (it.next()) |p| {
                std.debug.print("  {x}\n", .{&p.*.id.publicKey()});
            }
        } else if (std.mem.eql(u8, upper_cmd, "ID")) {
            std.debug.print("{x}\n", .{&router.base.identity.publicKey()});
        } else if (std.mem.eql(u8, upper_cmd, "CONNECT")) {
            handleConnect(allocator, rt, router.base, &tokens) catch |err| {
                log.warn("Could not handle connect command: {}", .{err});
            };
        } else if (std.mem.eql(u8, upper_cmd, "ECHO")) {
            handleEcho(allocator, rt, router, &tokens) catch |err| {
                log.warn("Could not handle echo command: {}", .{err});
            };
        } else if (std.mem.eql(u8, upper_cmd, "PING")) {
            handlePing(allocator, rt, router, &tokens) catch |err| {
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
    node: *peer.Node,
    tokens: *Tokens,
) !void {
    _ = rt; // autofix
    _ = allocator;
    const raw_address = tokens.rest();
    const addr = try net.parseIpAddress(raw_address);
    const p = try node.connect(addr);

    std.debug.print("Connected to peer {x}\n", .{&p.id.publicKey()});
}

fn handleEcho(
    allocator: std.mem.Allocator,
    rt: *zio.Runtime,
    node: *peer.RoutingNode,
    tokens: *Tokens,
) !void {
    _ = rt;
    const dest_id = try parsePeerId(tokens);

    const msg = try allocator.dupe(u8, tokens.rest());
    defer allocator.free(msg);

    try node.sendMessage(try .initPublic(dest_id), .command, .{ .echo = .{ .message = msg } });

    log.debug("Echo sent: {s}!", .{msg});
}

fn handlePing(
    allocator: std.mem.Allocator,
    rt: *zio.Runtime,
    node: *peer.RoutingNode,
    tokens: *Tokens,
) !void {
    _ = rt; // autofix
    const dest_id = try parsePeerId(tokens);

    const msg = try allocator.dupe(u8, tokens.rest());
    defer allocator.free(msg);

    try node.sendMessage(try .initPublic(dest_id), .request, .ping);
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
