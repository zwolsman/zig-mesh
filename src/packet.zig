const std = @import("std");

pub const ID = [16]u8;

pub const OpType = enum {
    request,
    response,
    command,
};

pub const Op = union(OpType) {
    request: ID,
    response: ID,
    command: void,
};

const PacketType = enum {
    ping,
    echo,
};

pub const Tag = union(PacketType) {
    ping: void,
    echo: struct { message: []u8 },
};

pub fn writePacket(writer: *std.Io.Writer, op: union(OpType) {
    request: void,
    response: ID,
    command: void,
}, tag: Tag) !?ID { // TODO: make an either type, only requests will result into an ID
    // Header
    try writer.writeInt(u8, @intFromEnum(op), .big);

    const id = switch (op) {
        .command => null,
        .request => id: {
            var request_id: [16]u8 = undefined;
            std.crypto.random.bytes(&request_id);
            try writer.writeAll(&request_id);
            break :id request_id;
        },
        .response => |id| request_id: {
            try writer.writeAll(&id);
            break :request_id null;
        },
    };

    try writer.writeInt(u8, @intFromEnum(tag), .big);

    // Body
    try writeTag(writer, tag);

    return id;
}

fn writeTag(writer: *std.Io.Writer, tag: Tag) !void {
    switch (tag) {
        .ping => {},
        .echo => |payload| {
            try writer.writeInt(u16, @intCast(payload.message.len), .big);
            try writer.writeAll(payload.message);
        },
    }
}

pub fn readPacket(reader: *std.Io.Reader) !struct { Op, Tag } {
    const op_type: OpType = @enumFromInt(try reader.takeInt(u8, .big));
    const op = op: switch (op_type) {
        .command => Op.command,
        .request => {
            const key = try reader.takeArray(@sizeOf(ID));
            break :op Op{ .request = key.* };
        },
        .response => {
            const key = try reader.takeArray(@sizeOf(ID));
            break :op Op{ .response = key.* };
        },
    };

    const packet_type: PacketType = @enumFromInt(try reader.takeInt(u8, .big));

    const tag = read_tag: switch (packet_type) {
        .ping => Tag.ping,
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
