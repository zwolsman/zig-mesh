const std = @import("std");

const flags = @import("flags");
const zio = @import("zio");

const Node = @import("./node.zig").Node;

const Flags = struct {
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

    const rt = try zio.Runtime.init(allocator, .{});
    defer rt.deinit();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    const options = flags.parse(args, "node", Flags, .{});

    const address = try if (options.listen_address) |raw_address|
        Flags.parseIpAddress(raw_address)
    else
        std.net.Address.parseIp4("127.0.0.1", 0);

    var node = try Node.init(allocator, std.crypto.sign.Ed25519.KeyPair.generate());
    defer node.deinit();

    try node.bind(rt, address);

    var node_job = try rt.spawn(Node.run, .{ &node, rt }, .{});
    node_job.detach(rt);

    try rt.run();
}
