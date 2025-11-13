const std = @import("std");

pub const Op = enum(u8) {
    request,
    response,
    command,
};

const PacketType = enum {
    ping,
    pong,
    echo,
};

pub const Tag = union(PacketType) {
    ping: void,
    pong: void,
    echo: struct { message: []u8 },
};

const MAX_PACKET_SIZE = 128;
const PACKET_VERSION: u8 = 1;

pub const HEADER_LEN = 3; // version(u8) + len(u16)

pub fn writePacket(writer: *std.Io.Writer, op: Op, tag: Tag) !void {
    // Header
    try writer.writeInt(u8, @intFromEnum(op), .big);
    try writer.writeInt(u8, @intFromEnum(tag), .big);

    // Body
    try writeTag(writer, tag);
    try writer.flush();
}

fn writeTag(writer: *std.Io.Writer, tag: Tag) !void {
    switch (tag) {
        .ping, .pong => {},
        .echo => |payload| {
            try writer.writeInt(u16, @intCast(payload.message.len), .big);
            try writer.writeAll(payload.message);
        },
    }
}

pub fn readPacket(reader: *std.Io.Reader) !struct { Op, Tag } {
    const op: Op = @enumFromInt(try reader.takeInt(u8, .big));
    const packet_type: PacketType = @enumFromInt(try reader.takeInt(u8, .big));

    const tag = read_tag: switch (packet_type) {
        .ping => Tag.ping,
        .pong => Tag.pong,
        .echo => {
            const msg_len = try reader.takeInt(u16, .big);
            break :read_tag Tag{ .echo = .{ .message = try reader.take(msg_len) } };
        },
    };

    return .{
        op,
        tag,
    };
}
