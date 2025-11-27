const std = @import("std");
const builtin = @import("builtin");

const flags = @import("flags");
const zio = @import("zio");

const mdns = @import("./mdns.zig");
const net = @import("./net.zig");
const Tty = @import("./tty.zig");
const peer = @import("peer.zig");
const protocol = @import("protocol.zig");

const Flags = struct {
    seed: ?u256 = null,
    listen_address: ?[]const u8 = null,
    interactive: bool = false,
    peer_discovery: bool = false,
    positional: struct {
        trailing: []const []const u8,
    },

    pub const switches = .{
        .listen_address = 'l',
        .interactive = 'i',
    };
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

    const address = try net.parseIpAddress(options.listen_address orelse "127.0.0.1:0");

    const kp = if (options.seed) |seed|
        try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(std.mem.toBytes(seed))
    else
        std.crypto.sign.Ed25519.KeyPair.generate();

    var node = try peer.Node.init(allocator, rt, .{ .full = kp });
    // Set up event handlers
    node.event_handler = .{
        .onPeerConnectedFn = onPeerConnected,
        .onMessageReceivedFn = onMessageReceived,
        .onPeerDisconnectedFn = onPeerDisconnected,
        .onErrorFn = onError,
    };

    defer node.deinit();

    std.log.debug("peer id: {x}", .{&node.identity.publicKey()});

    var node_job = try rt.spawn(peer.Node.start, .{ &node, address }, .{});
    node_job.detach(rt);

    if (options.peer_discovery) {
        var mdns_job = try rt.spawn(startMdns, .{ rt, &node }, .{});
        mdns_job.detach(rt);
    }

    var bootstrap_job = try rt.spawn(bootstrapNode, .{ &node, options.positional.trailing }, .{});
    bootstrap_job.detach(rt);

    if (options.interactive) {
        var tty_job = try rt.spawn(Tty.run, .{ allocator, rt, &node }, .{});
        tty_job.detach(rt);
    }

    try rt.run();
}

fn bootstrapNode(node: *peer.Node, bootstrap_addresses: []const []const u8) void {
    if (bootstrap_addresses.len == 0) return;

    for (bootstrap_addresses) |raw_address| {
        const addr = net.parseIpAddress(raw_address) catch |err| {
            std.log.debug("Could not parse {s}: {}", .{ raw_address, err });
            continue;
        };

        const p = node.connect(addr) catch |err| {
            std.log.debug("Could not connect to peer {f}: {}", .{ addr, err });
            continue;
        };

        std.log.debug("Connected to bootstrap peer {x}", .{&p.id.publicKey()});
        // TODO: query bootstrap peer for their peers
    }

    std.log.debug("Finished bootstrapping", .{});
}

const serviceName = "z-mesh";
fn startMdns(rt: *zio.Runtime, node: *peer.Node) void {
    var buf: [128]u8 = undefined;

    const addr = std.fmt.bufPrint(&buf, "tcp://{f}/", .{node.transport.server.?.socket.address.ip}) catch unreachable;

    var mdns_service = mdns.mDNSService.init(rt, "_z-mesh._tcp.local", addr) catch |err| {
        std.log.debug("Could not init mdns: {}", .{err});
        return;
    };
    defer mdns_service.deinit();

    mdns_service.run(rt) catch |err| {
        std.log.debug("Could not run mdns: {}", .{err});
        return;
    };

    mdns_service.query(rt) catch |err| {
        std.log.debug("Could not query mdns: {}", .{err});
        return;
    };
}

fn onPeerConnected(conn: *peer.Connection) void {
    std.debug.print("Peer connected: {x}\n", .{&conn.id.publicKey()});
}

fn onMessageReceived(peer_id: peer.Identity.PublicKey, op: protocol.Op, payload: protocol.Payload) void {
    std.debug.print("Message from {x}: {any} {any}\n", .{ &peer_id, op, payload });
}

fn onPeerDisconnected(peer_id: peer.Identity.PublicKey) void {
    std.debug.print("Peer disconnected: {x}\n", .{&peer_id});
}

fn onError(err: anyerror) void {
    std.debug.print("Error: {}\n", .{err});
}
