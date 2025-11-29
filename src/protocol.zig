const std = @import("std");

const noise = @import("noise.zig");

/// current supported message version
const version = 0x1;

/// minimum size of buffer for encoding/decoding messages
const min_buffer_len = 512;

pub const OpTag = enum(u8) {
    request = 0x0,
    response = 0x1,
    command = 0x2,
};

pub const Op = union(OpTag) {
    request: [16]u8,
    response: [16]u8,
    command: void,
};

/// Op when writing data
pub const WriteOp = union(OpTag) {
    request,
    response: [16]u8,
    command,
};

const PayloadTag = enum(u8) {
    ping = 0x0,
    echo = 0x1,
    route = 0x2,
};

pub const Payload = union(PayloadTag) {
    pub const Route = struct {
        destination: [32]u8,
        hops_len: u8,
        hops_buff: [16][32]u8,
        payload: []const u8,

        pub fn hops(self: *const Route) []const [32]u8 {
            return self.hops_buff[0..self.hops_len];
        }
    };

    ping: void,
    echo: struct { message: []u8 },
    route: Route,
};

const Header = struct {
    pub const ContentType = enum(u8) {
        handshake = 0x0,
        application_data = 0x1,
    };
    const Self = @This();
    const Size = @sizeOf(Self);

    version: u8,
    content_type: ContentType,
    len: u16,

    pub fn fromBytes(data: []u8) Self {
        const parsed_version = std.mem.readInt(u8, data[0..1], .big);
        const parsed_content_type: Header.ContentType = @enumFromInt(std.mem.readInt(u8, data[1..2], .big));
        const parsed_len = std.mem.readInt(u16, data[2..4], .big);

        return .{
            .version = parsed_version,
            .content_type = parsed_content_type,
            .len = parsed_len,
        };
    }
};

pub const Decoder = struct {
    const Self = @This();
    const log = std.log.scoped(.decoder);

    in: *std.Io.Reader,
    cipher: noise.CipherState,

    reader: std.Io.Reader,
    pub fn init(in: *std.Io.Reader, cipher: noise.CipherState, buff: []u8) Self {
        return .{
            .in = in,
            .cipher = cipher,
            .reader = .{
                .buffer = buff,
                .vtable = &.{
                    .stream = stream,
                    .readVec = readVec,
                },
                .seek = 0,
                .end = 0,
            },
        };
    }

    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        // This function writes exclusively to the buffer.
        _ = w;
        _ = limit;
        const decoder: *Self = @alignCast(@fieldParentPtr("reader", r));
        return readIndirect(decoder);
    }

    fn readVec(r: *std.Io.Reader, data: [][]u8) std.Io.Reader.Error!usize {
        // This function writes exclusively to the buffer.
        _ = data;
        const decoder: *Self = @alignCast(@fieldParentPtr("reader", r));
        return readIndirect(decoder);
    }

    fn readIndirect(decoder: *Self) std.Io.Reader.Error!usize {
        const reader = &decoder.reader;
        const in = decoder.in;

        log.debug("input buf: {any}", .{in.buffered()});

        const message_header = Header.fromBytes(try in.peek(Header.Size));

        const message_end: u16 = if (decoder.cipher.hasKey()) message_header.len + Header.Size + 16 else message_header.len + Header.Size;

        log.debug("peeked {any}", .{message_header});
        log.debug("buffer: {any}", .{in.buffered()});

        if (message_header.version != version) {
            return error.ReadFailed;
        }

        const expected_content_type: Header.ContentType = if (decoder.cipher.hasKey()) .application_data else .handshake;

        if (message_header.content_type != expected_content_type) {
            // TODO: set inner error maybe
            log.debug("Invalid content type (recv={})", .{message_header.content_type});
            return error.ReadFailed;
        }

        log.debug("Received message of size {d}", .{message_header.len});
        if (message_end > in.bufferedLen()) {
            log.debug("Filling more as message is not completely buffered: message end = {d}, buf len = {d}", .{ message_end, in.bufferedLen() });
            try in.fillMore();

            // Message not well read; returning 0.
            if (message_end > in.bufferedLen()) return 0;
        }
        log.debug("prepped buffer: {any}", .{in.buffered()});

        rebase(reader, message_end);
        in.toss(Header.Size); // already peaked
        const message_buffer = try in.take(message_end - Header.Size); // actual message

        const plaintext = decoder.cipher.decryptWithAd(reader.buffer[reader.end..], "", message_buffer) catch {
            return error.ReadFailed;
        };

        std.debug.assert(plaintext.len == message_header.len);
        log.debug("read bytes: {any}", .{plaintext});

        reader.end += plaintext.len;
        return plaintext.len;
    }

    fn rebase(r: *std.Io.Reader, capacity: usize) void {
        if (r.buffer.len - r.end >= capacity) return;
        const data = r.buffer[r.seek..r.end];
        @memmove(r.buffer[0..data.len], data);
        r.seek = 0;
        r.end = data.len;
        std.debug.assert(r.buffer.len - r.end >= capacity);
    }

    /// read op and payload from in
    pub fn read(self: *Self) !struct { Op, Payload } {
        const op_type: OpTag = @enumFromInt(try self.reader.takeInt(u8, .big));
        const op = op: switch (op_type) {
            .command => Op.command,
            .request => {
                const key = try self.reader.takeArray(16);
                break :op Op{ .request = key.* };
            },
            .response => {
                const key = try self.reader.takeArray(16);
                break :op Op{ .response = key.* };
            },
        };

        const tag: PayloadTag = @enumFromInt(try self.reader.takeInt(u8, .big));

        const payload = read_payload: switch (tag) {
            .ping => Payload.ping,
            .echo => {
                const msg_len = try self.reader.takeInt(u16, .big);
                break :read_payload Payload{ .echo = .{ .message = try self.reader.take(msg_len) } };
            },
            .route => {
                var route: Payload.Route = undefined;

                route.destination = (try self.reader.takeArray(32)).*;
                route.hops_len = try self.reader.takeInt(u8, .big);

                for (0..route.hops_len) |i| {
                    route.hops_buff[i] = (try self.reader.takeArray(32)).*;
                }

                const payload_len = try self.reader.takeInt(u16, .big);
                route.payload = try self.reader.take(payload_len);

                break :read_payload Payload{ .route = route };
            },
        };

        return .{
            op,
            payload,
        };
    }
};

pub const Encoder = struct {
    const Self = @This();
    const log = std.log.scoped(.encoder);

    out: *std.Io.Writer,
    cipher: noise.CipherState,
    writer: std.Io.Writer,

    pub fn init(out: *std.Io.Writer, cipher: noise.CipherState, buff: []u8) Self {
        return .{
            .cipher = cipher,
            .out = out,
            .writer = .{
                .buffer = buff,
                .vtable = &.{
                    .drain = drain,
                    .flush = flush,
                },
            },
        };
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const encoder: *Self = @alignCast(@fieldParentPtr("writer", w));
        const output = encoder.out;
        const output_buffer = try output.writableSliceGreedy(min_buffer_len);

        var plaintext_end: usize = 0;
        var buf_end: usize = 0;
        done: {
            {
                const buf = w.buffered();
                const in_len, const buf_len = try prepareCiphertextRecord(&encoder.cipher, output_buffer[buf_end..], buf);

                buf_end += buf_len;
                plaintext_end += in_len;
                if (in_len < buf.len) break :done;
            }
            for (data[0 .. data.len - 1]) |buf| {
                const in_len, const buf_len = try prepareCiphertextRecord(&encoder.cipher, output_buffer[buf_end..], buf);

                buf_end += buf_len;
                plaintext_end += in_len;
                if (in_len < buf.len) break :done;
            }
            const buf = data[data.len - 1];
            for (0..splat) |_| {
                const in_len, const buf_len = try prepareCiphertextRecord(&encoder.cipher, output_buffer[buf_end..], buf);

                buf_end += buf_len;
                plaintext_end += in_len;
                if (in_len < buf.len) break :done;
            }
        }

        output.advance(buf_end);
        return w.consume(plaintext_end);
    }

    fn flush(w: *std.Io.Writer) std.Io.Writer.Error!void {
        const encoder: *Encoder = @alignCast(@fieldParentPtr("writer", w));
        const output = encoder.out;
        const output_buffer = try output.writableSliceGreedy(min_buffer_len);
        const buf = w.buffered();

        _, const buf_len = try prepareCiphertextRecord(&encoder.cipher, output_buffer, buf);

        log.debug("wrote {any}", .{output_buffer[0..buf_len]});
        output.advance(buf_len);
        w.end = 0;
    }

    fn prepareCiphertextRecord(cipher: *noise.CipherState, output: []u8, data: []const u8) !struct { usize, usize } {
        var out = std.Io.Writer.fixed(output);
        try out.writeInt(u8, version, .big); // version always set to 1
        try out.writeInt(u8, @intFromEnum(if (cipher.hasKey()) Header.ContentType.application_data else Header.ContentType.handshake), .big);
        try out.writeInt(u16, @intCast(data.len), .big);

        const encrypted = cipher.encryptWithAd(out.unusedCapacitySlice(), "", data) catch {
            return error.WriteFailed;
        };

        out.advance(encrypted.len);

        return .{
            data.len,
            out.end,
        };
    }

    /// write an op and payload to internal buffer
    pub fn write(self: *Self, op: WriteOp, tag: Payload) !?[16]u8 {
        try self.writer.writeInt(u8, @intFromEnum(op), .big);

        const maybe_id: ?[16]u8 = id: switch (op) {
            .response => |id| break :id id,
            .request => {
                var request_id: [16]u8 = undefined;
                std.crypto.random.bytes(&request_id);
                break :id request_id;
            },
            .command => break :id null,
        };

        if (maybe_id) |id| {
            try self.writer.writeAll(&id);
        }

        try self.writer.writeInt(u8, @intFromEnum(tag), .big);

        switch (tag) {
            .ping => {},
            .echo => |echo| {
                try self.writer.writeInt(u16, @intCast(echo.message.len), .big);
                try self.writer.writeAll(echo.message);
            },
            .route => |route| {
                try self.writer.writeAll(&route.destination);
                try self.writer.writeInt(u8, @intCast(route.hops_len), .big);
                for (0..route.hops_len) |i| {
                    try self.writer.writeAll(&route.hops_buff[i]);
                }
                try self.writer.writeInt(u16, @intCast(route.payload.len), .big);
                try self.writer.writeAll(route.payload);
            },
        }

        try self.writer.flush();

        return maybe_id;
    }
};

test "Should be able to read message with empty key" {
    const data = [_]u8{ 0x1, 0x1, 0x0, 0x1, 0x0 }; // version, application data, len = 1, data = 0x0
    var in = std.Io.Reader.fixed(&data);
    var read_buffer: [512]u8 = undefined;
    var decoder = Decoder.init(&in, .empty, &read_buffer);

    var decoding_reader = &decoder.reader;

    try std.testing.expectEqual(0, try decoding_reader.takeInt(u8, .big));
}

test "Should be able to write message witih empty key" {
    var data: [512]u8 = undefined;
    var out = std.io.Writer.fixed(&data);
    var write_buffer: [512]u8 = undefined;

    var encoder = Encoder.init(&out, .empty, &write_buffer);

    var encoding_writer = &encoder.writer;
    try encoding_writer.writeInt(u8, 0x0, .big);

    try encoding_writer.flush();

    const result = out.buffered();

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x1, 0x0, 0x0, 0x1, 0x0 }, result);
}

test "Should be able to read message with key" {
    const data = [_]u8{ 0x01, 0x01, 0x00, 0x01, 0x01, 0x27, 0x03, 0xA8, 0x8A, 0xA9, 0xAD, 0x44, 0xA2, 0x5F, 0x70, 0xA2, 0x84, 0x7A, 0x2B, 0x63, 0x3F };
    var in = std.Io.Reader.fixed(&data);
    var read_buffer: [512]u8 = undefined;
    var decoder = Decoder.init(&in, .init(.ChaChaPoly, [_]u8{1} ** 32), &read_buffer);

    var decoding_reader = &decoder.reader;

    try std.testing.expectEqual(0, try decoding_reader.takeInt(u8, .big));
}

test "Should be able to write message with key" {
    var data: [512]u8 = undefined;
    var out = std.io.Writer.fixed(&data);
    var write_buffer: [512]u8 = undefined;

    var encoder = Encoder.init(&out, .init(.ChaChaPoly, [_]u8{1} ** 32), &write_buffer);

    var encoding_writer = &encoder.writer;
    try encoding_writer.writeInt(u8, 0x0, .big);

    try encoding_writer.flush();

    const result = out.buffered();

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x01, 0x00, 0x01, 0x01, 0x27, 0x03, 0xA8, 0x8A, 0xA9, 0xAD, 0x44, 0xA2, 0x5F, 0x70, 0xA2, 0x84, 0x7A, 0x2B, 0x63, 0x3F }, result);
}
