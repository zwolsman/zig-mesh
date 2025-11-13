const std = @import("std");

pub const Op = enum(u8) {
    request,
    response,
    command,
};

pub const Tag = enum(u8) {
    ping,
    pong,
    echo,
};

const MAX_PACKET_SIZE = 128;
const PACKET_VERSION: u8 = 1;

pub const HEADER_LEN = 5;

pub fn writePacket(writer: *std.Io.Writer, op: Op, tag: Tag, payload: anytype) !void {
    var packet_buffer: [MAX_PACKET_SIZE]u8 = undefined;
    var packet_writer = std.Io.Writer.fixed(&packet_buffer);

    if (@TypeOf(payload) != @TypeOf(null)) {
        try payload.writeTo(&packet_writer);
    }
    // if (payload) |p| {

    // }

    const packet_data = packet_writer.buffered();

    // Header
    try writer.writeInt(u8, 1, .big); // version always set to 1
    try writer.writeInt(u16, @intCast(packet_data.len), .big);
    try writer.writeInt(u8, @intFromEnum(op), .big);
    try writer.writeInt(u8, @intFromEnum(tag), .big);

    // Body
    try writer.writeAll(packet_data);
    try writer.flush();
}

pub fn readPacket(reader: *std.Io.Reader) !struct { Op, Tag, []u8 } {
    std.log.debug("Trying to read packet..", .{});

    const version = try reader.takeInt(u8, .big);
    std.debug.assert(version == PACKET_VERSION);

    const len = try reader.takeInt(u16, .big);
    const op: Op = @enumFromInt(try reader.takeInt(u8, .big));
    const tag: Tag = @enumFromInt(try reader.takeInt(u8, .big));
    const data = try reader.take(len);

    return .{ op, tag, data };
}

pub const Echo = struct {
    msg: []u8,

    pub fn writeTo(self: Echo, writer: *std.Io.Writer) !void {
        try writer.writeInt(u16, @intCast(self.msg.len), .big);
        try writer.writeAll(self.msg);
        try writer.flush();
    }

    pub fn readFrom(reader: *std.Io.Reader) !Echo {
        const len = try reader.takeInt(u16, .big);
        const msg = try reader.take(len);

        return .{
            .msg = msg,
        };
    }
};
