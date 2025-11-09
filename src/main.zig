const std = @import("std");

const flags = @import("flags");
const zio = @import("zio");

const Node = @import("./node.zig").Node;

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
    defer node_job.cancel(rt);

    var bootstrap_job = try rt.spawn(bootstrapNode, .{ &node, rt, options.positional.trailing }, .{});
    defer bootstrap_job.cancel(rt);

    try rt.run();

    bootstrap_job.join(rt);
    try node_job.join(rt);
}

fn bootstrapNode(node: *Node, rt: *zio.Runtime, bootstrap_addresses: []const []const u8) void {
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
}
