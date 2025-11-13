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

pub const HEADER_LEN = 5;

pub fn writePacket(writer: *std.Io.Writer, op: Op, tag: Tag) !void {
    var packet_buffer: [MAX_PACKET_SIZE]u8 = undefined;
    var packet_writer = std.Io.Writer.fixed(&packet_buffer);

    try writeTag(&packet_writer, tag);
    const packet_data = packet_writer.buffered();

    // Header
    try writer.writeInt(u8, 1, .big); // version always set to 1
    try writer.writeInt(u16, @intCast(packet_data.len), .big); // TODO: move to connection client
    try writer.writeInt(u8, @intFromEnum(op), .big);
    try writer.writeInt(u8, @intFromEnum(tag), .big);

    // Body
    try writer.writeAll(packet_data);
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
    std.log.debug("Trying to read packet..", .{});

    const version = try reader.takeInt(u8, .big);
    std.debug.assert(version == PACKET_VERSION); // TODO: deprecated; handled in connection client!

    const len = try reader.takeInt(u16, .big);
    _ = len; // TODO: deprecated; handled in connection client!

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
