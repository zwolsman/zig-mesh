const std = @import("std");

const flags = @import("flags");
const zio = @import("zio");

const mdns = @import("./mdns.zig");
const net = @import("./net.zig");
const Node = @import("./node.zig").Node;
const Packet = @import("./packet.zig");
const Tty = @import("./tty.zig");

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

    const seed = std.mem.bytesToValue(u256, &kp.secret_key.seed());
    std.log.debug("seed: {d}", .{seed});

    var node = try Node.init(allocator, kp);
    defer node.deinit();

    try node.bind(rt, address);

    var node_job = try rt.spawn(Node.run, .{ &node, rt }, .{});
    node_job.detach(rt);

    const service_name = try std.fmt.allocPrint(allocator, "tcp://{x}", .{&node.id.public_key});
    defer allocator.free(service_name);

    var mdns_service = try mdns.mDNSService.init(rt, .{ .name = service_name, .port = node.server.?.socket.address.ip.getPort() });
    defer mdns_service.deinit();

    var mdns_job = try rt.spawn(mdns.mDNSService.run, .{ &mdns_service, rt }, .{});
    mdns_job.detach(rt);

    // try to query
    try mdns_service.query(rt);

    var bootstrap_job = try rt.spawn(bootstrapNode, .{ rt, &node, options.positional.trailing }, .{});
    bootstrap_job.detach(rt);

    if (options.interactive) {
        var tty_job = try rt.spawn(Tty.run, .{ allocator, rt, &node }, .{});
        tty_job.detach(rt);
    }

    try rt.run();
}

fn bootstrapNode(rt: *zio.Runtime, node: *Node, bootstrap_addresses: []const []const u8) void {
    if (bootstrap_addresses.len == 0) return;

    for (bootstrap_addresses) |raw_address| {
        const addr = net.parseIpAddress(raw_address) catch |err| {
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
