const std = @import("std");

const zio = @import("zio");

const Node = @import("./node.zig").Node;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    const rt = try zio.Runtime.init(allocator, .{});
    defer rt.deinit();

    var node = try Node.init(allocator, std.crypto.sign.Ed25519.KeyPair.generate());
    defer node.deinit();

    try rt.runUntilComplete(Node.run, .{ &node, rt }, .{});
}
