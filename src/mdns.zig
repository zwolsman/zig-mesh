// Inspired by https://github.com/diogok/je-dns/tree/main
const std = @import("std");
const builtin = @import("builtin");

const zio = @import("zio");

/// Query to find all local network services.
const mdns_services_query = "_services._dns-sd._udp.local";
/// Resource Type for local network services.
const mdns_services_resource_type: ResourceType = .PTR;

/// Multicast IPv6 Address for mDNS.
const mdns_ipv6_address = zio.net.Address.fromStd(std.net.Address.initIp6([16]u8{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfb }, 5353, 0, 0));

/// Multicast IPv4 Address for mDNS.
const mdns_ipv4_address = zio.net.Address.fromStd(std.net.Address.parseIp("224.0.0.251", 5353) catch unreachable); //std.net.Address.initIp4([4]u8{ 224, 0, 0, 251 }, 5353));

/// Max size of a DNS name, like a full host.
const NAME_MAX_SIZE = 253;

/// Max size of a hostname.
const HOST_NAME_MAX = 64;

/// Size of a UDP packet.
const PACKET_SIZE = 512;

/// If the message is a query (like question) or a reply (answer)
const QueryOrReply = enum(u1) { query, reply };

/// Possible reply code, used mainly to identify errors
const ReplyCode = enum(u4) {
    no_error = 0,
    format_error = 1,
    server_fail = 2,
    non_existent_domain = 3,
    not_implemented = 4,
    refused = 5,
    domain_should_not_exist = 6,
    resource_record_should_not_exist = 7,
    not_authoritative = 8,
    not_in_zone = 9,
    _,
};

/// Resource Type of a Record
pub const ResourceType = enum(u16) {
    /// Host Address
    A = 1,
    /// Authorittive nameserver
    NS = 2,
    /// Canonical name for an alias
    CNAME = 5,
    /// Start of a zone of Authority
    SOA = 6,
    /// Domain name pointer
    PTR = 12,
    /// Mail exchange
    MX = 15,
    /// text strings
    TXT = 16,
    /// IP6 Address
    AAAA = 28,
    /// Server Selection
    SRV = 33,

    AFSDB = 18,
    APL = 42,
    CAA = 257,
    CERT = 60,
    CDS = 37,
    CSYNC = 62,
    DHCID = 49,
    DLV = 32769,
    DNAME = 39,
    DNSKEY = 48,
    DS = 43,
    EUI48 = 108,
    EUI64 = 109,
    HINFO = 13,
    HIP = 55,
    HTTPS = 65,
    IPSECKEY = 45,
    KEY = 25,
    KX = 36,
    LOC = 29,
    NAPTR = 35,
    NSEC = 47,
    NSEC3 = 50,
    NSEC3PARAM = 51,
    OPENPGPKEY = 61,
    RP = 17,
    RRSIG = 46,
    SIG = 24,
    SMIMEA = 53,
    SSHFP = 44,
    SVCB = 64,
    TA = 32768,
    TKEY = 249,
    TLSA = 22,
    TSIG = 250,
    URI = 256,
    ZONEMD = 63,
    _,
};

/// Resource class of a Record
const ResourceClass = enum(u16) {
    /// Internet
    IN = 1,
    _,
};

/// Type of message
const Opcode = enum(u4) {
    query = 0,
    iquery = 1,
    status = 2,
    _,
};
/// The first part of a DNS Message.
const Header = packed struct {
    /// Generated ID on the request,
    /// can be used to match a request and response.
    ID: u16 = 0,
    /// Flags have information about both query or answer.
    flags: Flags = Flags{},
    /// Number of questions, both in query and answer.
    number_of_questions: u16 = 0,
    /// Number of answers on responses.
    /// This is the common record response.
    number_of_answers: u16 = 0,
    /// Number of authority records on responses.
    /// This are responses if the server is the authority one.
    number_of_authority_resource_records: u16 = 0,
    /// Number of answers on responses.
    /// These are additional records, apart from the requested ones.
    number_of_additional_resource_records: u16 = 0,

    /// Read headers from a stream.
    pub fn read(reader: *std.Io.Reader) !@This() {
        return @This(){
            .ID = try reader.takeInt(u16, .big),
            .flags = try Flags.read(reader),
            .number_of_questions = try reader.takeInt(u16, .big),
            .number_of_answers = try reader.takeInt(u16, .big),
            .number_of_authority_resource_records = try reader.takeInt(u16, .big),
            .number_of_additional_resource_records = try reader.takeInt(u16, .big),
        };
    }

    /// Write headers to a stream.
    pub fn writeTo(self: @This(), writer: *std.Io.Writer) !void {
        try writer.writeInt(u16, self.ID, .big);

        try self.flags.writeTo(writer);

        try writer.writeInt(u16, self.number_of_questions, .big);
        try writer.writeInt(u16, self.number_of_answers, .big);
        try writer.writeInt(u16, self.number_of_authority_resource_records, .big);
        try writer.writeInt(u16, self.number_of_additional_resource_records, .big);
    }
};

/// Flags for a DNS message, for query and answer.
const Flags = packed struct {
    query_or_reply: QueryOrReply = .query,
    opcode: Opcode = .query,
    authoritative_answer: bool = false,
    truncation: bool = false,
    recursion_desired: bool = false,
    recursion_available: bool = false,
    padding: u3 = 0,
    response_code: ReplyCode = .no_error,

    /// Read flags from a reader.
    pub fn read(reader: *std.Io.Reader) !Flags {
        var flag_bits = try reader.takeInt(u16, .big);
        if (builtin.cpu.arch.endian() == .little) {
            flag_bits = @bitReverse(flag_bits);
        }
        return @bitCast(flag_bits);
    }

    /// Write flags to a stream.
    pub fn writeTo(self: @This(), writer: *std.Io.Writer) !void {
        var flag_bits: u16 = @bitCast(self);
        if (builtin.cpu.arch.endian() == .little) {
            flag_bits = @bitReverse(flag_bits);
        }
        try writer.writeInt(u16, flag_bits, .big);
    }
};

/// Question for a resource type. Sometimes also returned on Answers.
const Question = struct {
    /// Name is usually the domain, but also any query object.
    name: []const u8,
    resource_type: ResourceType,
    resource_class: ResourceClass = .IN,

    /// Read question from stream.
    pub fn read(buffer: []u8, reader: *std.Io.Reader) !Question {
        // There are special rules for reading a name.
        const name = try readNameBuffer(buffer, reader);

        // var reader = stream.reader();
        const r_type = try reader.takeInt(u16, .big);
        const r_class = try reader.takeInt(u16, .big);

        return .{
            .name = name,
            .resource_type = @enumFromInt(r_type),
            .resource_class = @enumFromInt(r_class & 0b1),
        };
    }

    /// Write the Question to a stream.
    pub fn writeTo(self: @This(), writer: *std.Io.Writer) !void {
        try writeName(writer, self.name);
        try writer.writeInt(u16, @intFromEnum(self.resource_type), .big);
        try writer.writeInt(u16, @intFromEnum(self.resource_class), .big);
    }
};

/// The information about a DNS Record
const Record = struct {
    name: []const u8,
    resource_type: ResourceType,
    resource_class: ResourceClass = .IN,
    /// Expiration in econds
    ttl: u32 = 0,
    data: RecordData,

    pub fn read(buffer: []u8, reader: *std.Io.Reader) !Record {
        std.debug.assert(buffer.len > NAME_MAX_SIZE);

        const name = try readNameBuffer(buffer[0..NAME_MAX_SIZE], reader);

        const r_type = try reader.takeInt(u16, .big);
        const r_class = try reader.takeInt(u16, .big);
        const ttl = try reader.takeInt(u32, .big);

        const resource_type: ResourceType = @enumFromInt(r_type);
        const resource_class: ResourceClass = @enumFromInt(r_class & 0b1);

        const record_data = try RecordData.read(buffer[NAME_MAX_SIZE..], resource_type, reader);

        return .{
            .resource_type = resource_type,
            .resource_class = resource_class,
            .ttl = ttl,
            .name = name,
            .data = record_data,
        };
    }

    /// Write resource to stream.
    pub fn writeTo(self: @This(), writer: *std.Io.Writer) !void {
        try writeName(writer, self.name);
        try writer.writeInt(u16, @intFromEnum(self.resource_type), .big);
        try writer.writeInt(u16, @intFromEnum(self.resource_class), .big);
        try writer.writeInt(u32, self.ttl, .big);
        try self.data.writeTo(writer);
    }
};

/// The data that a Record hold,
/// depends on the resource class.
const RecordData = union(enum) {
    /// IPv4 or IPv6 address, for records like A or AAAA.
    ip: std.net.Address,
    /// Services information
    srv: SRV,
    /// For TXT records, a list of strings
    txt: []const u8,
    /// For PTR, likely a new domain, used in dns-sd for example.
    /// Works like a domain name
    ptr: []const u8,
    /// For other types, cotains the raw uninterpreted data.
    raw: []const u8,

    /// Read the record data from stream, need to know the resource type.
    pub fn read(buffer: []u8, resource_type: ResourceType, reader: *std.Io.Reader) !RecordData {

        // Make sure we leave the stream at the end of the data.
        const data_len = try reader.takeInt(u16, .big);
        const pos = reader.seek;

        const len = data_len;
        std.debug.assert(buffer.len >= len);

        switch (resource_type) {
            .A => {
                const bytes = try reader.takeArray(4);

                return .{ .ip = std.net.Address.initIp4(bytes.*, 0) };
            },
            .AAAA => {
                const bytes = try reader.takeArray(16);

                return .{ .ip = std.net.Address.initIp6(bytes.*, 0, 0, 0) };
            },
            .PTR => {
                return .{ .ptr = try readNameBuffer(buffer, reader) };
            },
            .SRV => {
                return .{
                    .srv = SRV{
                        .weight = try reader.takeInt(u16, .big),
                        .priority = try reader.takeInt(u16, .big),
                        .port = try reader.takeInt(u16, .big),
                        .target = try readNameBuffer(buffer, reader),
                    },
                };
            },
            .TXT => {
                const data = try reader.take(len);

                return .{ .txt = data };
            },
            else => {
                const data = try reader.take(len);

                return .{ .raw = data };
            },
        }

        // assert that we read the complete message
        std.debug.assert(reader.seek == pos + len);
    }

    /// Write the resource data to a stream.
    pub fn writeTo(self: @This(), writer: *std.Io.Writer) !void {
        switch (self) {
            .ip => |address| {
                switch (address.any.family) {
                    std.posix.AF.INET => {
                        try writer.writeInt(u16, 4, .big);
                        try writer.writeInt(u32, std.mem.nativeToBig(u32, address.in.sa.addr), .big);
                    },
                    std.posix.AF.INET6 => {
                        try writer.writeInt(u16, 16, .big);
                        for (address.in6.sa.addr) |byte| {
                            try writer.writeInt(u8, byte, .big);
                        }
                    },
                    else => {
                        unreachable;
                    },
                }
            },
            .srv => |srv| {
                try writer.writeInt(u16, @truncate(srv.target.len + 2 + 6), .big);
                try writer.writeInt(u16, srv.weight, .big);
                try writer.writeInt(u16, srv.priority, .big);
                try writer.writeInt(u16, srv.port, .big);
                try writeName(writer, srv.target);
            },
            .ptr => |ptr| {
                try writer.writeInt(u16, @truncate(ptr.len + 2), .big);
                try writeName(writer, ptr);
            },
            .raw, .txt => |bytes| {
                try writer.writeInt(u16, @truncate(bytes.len), .big);
                _ = try writer.write(bytes);
            },
        }
    }
};

/// Details of RecordData for SRV type.
const SRV = struct {
    priority: u16,
    weight: u16,
    port: u16,
    target: []const u8,
};

/// Details of RecordData for TXT type.
const TXTIter = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn next(self: *@This()) ?[]const u8 {
        if (self.pos >= self.data.len) {
            return null;
        }
        const txt_len = self.data[self.pos];
        self.pos += 1;
        defer self.pos += txt_len;
        return self.data[self.pos .. self.pos + txt_len];
    }

    pub fn toBytes(buffer: []u8, txt: []const []const u8) []const u8 {
        var pos: usize = 0;
        for (txt) |t| {
            buffer[pos] = @truncate(t.len);
            pos += 1;
            std.mem.copyForwards(u8, buffer[pos..], t);
            pos += t.len;
        }
        return buffer[0..pos];
    }

    pub fn calcSize(txt: []const []const u8) usize {
        var pos: usize = 0;
        for (txt) |t| {
            pos += t.len + 1;
        }
    }
};

/// Writes a name in the format of DNS names.
/// Each "section" (the parts excluding the ".") is written
/// as first a byte with the length them the actual data.
/// The last byte is a 0 indicating the end (no more section).
fn writeName(writer: *std.Io.Writer, name: []const u8) !void {
    var labels_iter = std.mem.splitScalar(u8, name, '.');
    while (labels_iter.next()) |label| {
        const len: u8 = @truncate(label.len);
        _ = try writer.writeByte(len);
        _ = try writer.write(label);
    }
    _ = try writer.writeByte(0);
}

/// Read a name from a DNS message.
/// DNS names has a format that require havin access to the whole message.
/// Each section (.) is prefixed with the length of that section.
/// The end is byte '0'.
/// A section maybe a pointer to another section elsewhere.
fn readNameBuffer(buffer: []u8, reader: *std.Io.Reader) ![]const u8 {
    std.debug.assert(buffer.len >= NAME_MAX_SIZE);

    var name_len: usize = 0;

    var seekBackTo: u64 = 0;

    while (true) {
        const len = try reader.takeByte();
        if (len == 0) { // if len is zero, there is no more data
            break;
        } else if (len >= 192) { // a length starting with 0b11 is a pointer
            const ptr0: u8 = len & 0b00111111; // remove the points bits to get the
            const ptr1: u8 = try reader.takeByte(); // the following byte is part of the pointer
            // Join the two bytes to get the address of the rest of the name
            const ptr = (@as(u16, ptr0) << 8) + @as(u16, ptr1);
            // save current position
            if (seekBackTo == 0) {
                seekBackTo = reader.seek;
            }
            reader.seek = ptr;
        } else {
            // If we already have a section, append a "."
            if (name_len > 0) {
                buffer[name_len] = '.';
                name_len += 1;
            }

            // read the sepecificed len
            const data = try reader.take(len);

            @memcpy(buffer[name_len .. name_len + len], data);
            name_len += len;
        }
    }

    if (seekBackTo > 0) {
        reader.seek = seekBackTo;
    }

    return buffer[0..name_len];
}

/// Our service definition.
pub const Service = struct {
    name: []const u8,
    port: u16,
};

pub const mDNSService = struct {
    const log = std.log.scoped(.mdns);

    const BroadcastSocket = struct {
        address: zio.net.Address,
        socket: zio.net.Socket,
    };
    sockets: [1]BroadcastSocket,
    service: Service,

    /// Internal buffers
    name_buffer: [NAME_MAX_SIZE]u8 = undefined,
    /// Internal buffers
    host_buffer: [NAME_MAX_SIZE]u8 = undefined,
    /// Internal buffers
    hostname_buffer: [NAME_MAX_SIZE]u8 = undefined,
    /// Internal buffers
    service_name_buffer: [NAME_MAX_SIZE]u8 = undefined,
    /// Internal buffers
    target_buffer: [NAME_MAX_SIZE]u8 = undefined,
    /// Internal buffers
    addresses_buffer: [32]std.net.Address = undefined,

    pub fn init(rt: *zio.Runtime, service: Service) !mDNSService {
        // _ = rt;
        const flags: u32 = std.posix.SOCK.DGRAM | std.posix.SOCK.CLOEXEC | std.posix.SOCK.NONBLOCK;
        const sock_fd = try std.posix.socket(mdns_ipv4_address.ip.any.family, flags, 0);

        var socket = zio.net.Socket{
            .address = mdns_ipv4_address,
            .handle = sock_fd,
        };
        try socket.setReuseAddress(true);
        try socket.setReusePort(true);

        const local_addr = std.net.Address.initIp4([4]u8{ 0, 0, 0, 0 }, 5353);

        try socket.bind(rt, zio.net.Address.fromStd(local_addr));
        // try std.posix.bind(sock, &local_addr.any, local_addr.getOsSockLen());
        try setupMulticast(sock_fd, mdns_ipv4_address.toStd(), .{});

        return .{
            .sockets = [1]BroadcastSocket{.{ .address = mdns_ipv4_address, .socket = socket }},
            .service = service,
        };
    }

    pub fn shutdown(self: *mDNSService, rt: *zio.Runtime) void {
        _ = self; // autofix
        _ = rt; // autofix
    }

    pub fn deinit(self: *mDNSService) void {
        _ = self; // autofix
    }

    /// This will query the network for other instances of this service.
    /// The next call to `handle` will probably return new peers.
    pub fn query(self: *mDNSService, rt: *zio.Runtime) !void {
        var buffer: [512]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);

        // Prepare the query message
        const header = Header{
            .ID = 0,
            .number_of_questions = 1,
        };
        try header.writeTo(&writer);

        const question = Question{
            .name = self.service.name,
            .resource_type = .PTR,
        };
        try question.writeTo(&writer);

        for (self.sockets) |s| {
            const len = s.socket.sendTo(rt, s.address, writer.buffered()) catch |err| {
                log.debug("Could not send to {f}: {}", .{ s.address, err });
                continue;
            };

            log.debug("Wrote {} bytes to socket: {any}", .{ len, writer.buffered() });
        }
    }

    pub fn run(self: *mDNSService, rt: *zio.Runtime) !void {
        for (self.sockets) |s| {
            var task = try rt.spawn(receive, .{ self, rt, s.socket }, .{});
            task.detach(rt);
        }
    }

    fn receive(self: *mDNSService, rt: *zio.Runtime, socket: zio.net.Socket) void {
        log.debug("Listening on: {f}", .{socket.address});
        defer log.warn("Stopped listening on {f}!", .{socket.address});

        var buffer: [PACKET_SIZE]u8 = undefined;
        while (!rt.shutting_down.raw) {
            const result = socket.receiveFrom(rt, &buffer) catch |err| {
                log.debug("Err receiving: {}", .{err});
                continue;
            };

            if (result.len == 0) break;

            var reader = std.Io.Reader.fixed(buffer[0..result.len]);
            var message_reader = MessageReader.init(&reader) catch |err| {
                log.debug("Err parsing message: {}", .{err});
                continue;
            };

            log.debug("Received message ({f}): {}", .{ result.from, message_reader.header.flags.query_or_reply });

            switch (message_reader.header.flags.query_or_reply) {
                .query => self.handleQuery(&message_reader) catch |err| {
                    log.debug("Could not handle query: {}", .{err});
                    continue;
                },
                .reply => self.handleReply(&message_reader) catch |err| {
                    log.debug("Could not handle reply: {}", .{err});
                    continue;
                },
            }
        }
    }

    fn handleQuery(self: *mDNSService, reader: *MessageReader) !void {
        log.debug("Received query", .{});
        while (try reader.nextQuestion()) |q| {
            if (std.mem.eql(u8, q.name, self.service.name)) {
                log.debug("I have to respond!", .{});
            } else {
                log.debug("Not our service name: {s}", .{q.name});
            }
        }
    }

    fn handleReply(self: *mDNSService, reader: *MessageReader) !void {
        log.debug("Received reply", .{});

        var peer: Peer = Peer{};

        while (try reader.nextRecord()) |record| {
            log.debug("Received {} resource", .{record.resource_type});
            switch (record.resource_type) {
                .PTR => {
                    // PTR will have the a service instance
                    // confirm this is the service we want
                    if (std.mem.eql(u8, record.name, self.service.name)) {
                        std.mem.copyForwards(u8, &self.name_buffer, record.data.ptr);
                        peer.name = self.name_buffer[0..record.data.ptr.len];
                        if (std.mem.eql(u8, peer.name, self.serviceName())) {
                            // this is our own message
                            // return null;
                        }
                        peer.ttl_in_seconds = record.ttl;
                    } else {
                        log.debug("Drop {s}", .{record.name});
                    }
                },
                .TXT => {},
                else => {},
            }
        }
    }

    fn serviceName(self: *@This()) []const u8 {
        // Get our own hostname
        _ = std.c.gethostname(&self.hostname_buffer, HOST_NAME_MAX);
        const hostname = std.mem.span(@as([*c]u8, &self.hostname_buffer));

        // name of this service instance
        const full_service_name = std.fmt.bufPrint(
            &self.service_name_buffer,
            "{s}.{s}",
            .{
                hostname,
                self.service.name,
            },
        ) catch unreachable;

        return full_service_name;
    }
};

const MessageReader = struct {
    buffer: [PACKET_SIZE]u8 = undefined,

    reader: *std.Io.Reader,
    header: Header,

    q: usize = 0,
    r: usize = 0,

    pub fn init(reader: *std.Io.Reader) !MessageReader {
        return .{
            .reader = reader,
            .header = try Header.read(reader),
        };
    }

    /// Return the next(or frst) question from the message.
    /// Returns null when there are no more questions.
    pub fn nextQuestion(self: *@This()) !?Question {
        if (self.q < self.header.number_of_questions) {
            self.q += 1;
            return try .read(&self.buffer, self.reader);
        } else {
            return null;
        }
    }

    /// Return the next(or frst) record from the message.
    /// Returns null when there are no more record.
    pub fn nextRecord(self: *@This()) !?Record {
        const max = self.header.number_of_answers + self.header.number_of_additional_resource_records + self.header.number_of_authority_resource_records;
        if (self.r < max) {
            self.r += 1;
            return try .read(&self.buffer, self.reader);
        } else {
            return null;
        }
    }
};

/// Common options for Multicast setupts.
pub const MulticastOptions = struct {
    /// How many network hops can the message go.
    /// 0 is only the original machine.
    /// 1 is original machine + 1, which usually means your direct network (eth, wi-fi, vpn).
    hops: u8 = 1,
    /// Loop means the sender will receive it's own messages.
    /// Useful to debug.
    loop: bool = true,
};

/// Get the "any" address of any address.
/// Example: "0.0.0.0" or "::"
pub fn getAny(address: std.net.Address) !std.net.Address {
    switch (address.any.family) {
        std.posix.AF.INET => {
            return std.net.Address.initIp4([4]u8{ 0, 0, 0, 0 }, address.getPort());
        },
        std.posix.AF.INET6 => {
            return std.net.Address.initIp6(std.mem.zeroes([16]u8), address.getPort(), 0, 0);
        },
        else => {
            return error.UnkownAddressFamily;
        },
    }
}

/// Setup multicast options, specially for using mDNS.
/// Works for IPv4 and IPv6.
/// Will setup: Multicast interface (IF), Loop, Hops and Membership.
pub fn setupMulticast(
    sock: std.posix.socket_t,
    address: std.net.Address,
    options: MulticastOptions,
) !void {
    switch (address.any.family) {
        std.posix.AF.INET => {
            const any = try getAny(address);
            // Setup for multicast.
            // For IPv4, you set the multicast interface to the 'any' address.

            try std.posix.setsockopt(
                sock,
                IPV4,
                IP_MULTICAST_IF,
                std.mem.asBytes(&any.in.sa.addr),
            );
            // Should receive it's own messages
            var loop: u1 = 0;
            if (options.loop) {
                loop = 1;
            }
            try std.posix.setsockopt(
                sock,
                IPV4,
                IP_MULTICAST_LOOP,
                &std.mem.toBytes(@as(c_int, loop)),
            );
            // How many 'hops' (ie.: network machines) it will cross.
            // Set to 1 to use only on immediate network (own machine + 1).
            try std.posix.setsockopt(
                sock,
                IPV4,
                IP_MULTICAST_TTL,
                &std.mem.toBytes(@as(c_int, options.hops)),
            );

            // This will add our address to receive messages on the multicast "any" address.
            const membership = extern struct {
                addr: u32,
                any: u32,
            }{
                .addr = address.in.sa.addr,
                .any = any.in.sa.addr,
            };
            try std.posix.setsockopt(
                sock,
                IPV4,
                IP_ADD_MEMBERSHIP,
                std.mem.asBytes(&membership),
            );
        },
        std.posix.AF.INET6 => {
            // Setup for multicast.
            // For IPv6 you choose a network interface.
            // 0 means default
            // Should we loop and do all interfaces?
            try std.posix.setsockopt(
                sock,
                IPV6,
                IPV6_MULTICAST_IF,
                &std.mem.toBytes(@as(c_int, 0)),
            );
            // How many 'hops' (ie.: network machines) it will cross.
            // Set to 1 to use only on immediate network (own machine + 1).
            try std.posix.setsockopt(
                sock,
                IPV6,
                IPV6_MULTICAST_HOPS,
                &std.mem.toBytes(@as(c_int, options.hops)),
            );
            // Should receive it's own messages
            var loop: u1 = 0;
            if (options.loop) {
                loop = 1;
            }
            try std.posix.setsockopt(
                sock,
                IPV6,
                IPV6_MULTICAST_LOOP,
                &std.mem.toBytes(@as(c_int, loop)),
            );

            // Ipv6 Add membership to the default interface (0)
            const membership = extern struct {
                addr: [16]u8,
                index: c_uint,
            }{
                .addr = address.in6.sa.addr,
                .index = 0,
            };
            try std.posix.setsockopt(
                sock,
                IPV6,
                IPV6_ADD_MEMBERSHIP,
                std.mem.asBytes(&membership),
            );
        },
        else => {
            return error.UnkownAddressFamily;
        },
    }
}

const c = @cImport({
    switch (builtin.os.tag) {
        .windows => @cInclude("ws2tcpip.h"),
        else => @cInclude("arpa/inet.h"),
    }
});

const IPV4 = c.IPPROTO_IP;
const IPV6 = c.IPPROTO_IPV6;

const IP_MULTICAST_IF = c.IP_MULTICAST_IF;
const IP_MULTICAST_TTL = c.IP_MULTICAST_TTL;
const IP_MULTICAST_LOOP = c.IP_MULTICAST_LOOP;
const IP_ADD_MEMBERSHIP = c.IP_ADD_MEMBERSHIP;

const IPV6_MULTICAST_IF = c.IPV6_MULTICAST_IF;
const IPV6_MULTICAST_HOPS = c.IPV6_MULTICAST_HOPS;
const IPV6_MULTICAST_LOOP = c.IPV6_MULTICAST_LOOP;
const IPV6_ADD_MEMBERSHIP = if (builtin.os.tag == .macos) c.IPV6_JOIN_GROUP else c.IPV6_ADD_MEMBERSHIP;

/// This is another instance of our service in this network.
pub const Peer = struct {
    /// TTL in seconds of this DNS records.
    ttl_in_seconds: u32 = 0,
    /// addresses of this Peer.
    addresses: []const std.net.Address = &[_]std.net.Address{},
    /// full name of this instance.
    name: []const u8 = "",

    pub fn eql(self: @This(), other_peer: @This()) bool {
        return std.mem.eql(u8, self.name, other_peer.name);
    }
};

test "Write and read the same message" {
    std.testing.log_level = .debug;
    var buffer: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);

    var header = Header{};
    header.ID = 38749;
    header.flags.recursion_available = true;
    header.flags.recursion_desired = true;
    header.number_of_questions = 1;
    header.number_of_additional_resource_records = 2;
    try header.writeTo(&writer);

    const question = Question{
        .name = "example_q.com",
        .resource_type = .A,
    };
    try question.writeTo(&writer);

    const record0 = Record{
        .name = "example_0.com",
        .resource_type = .A,
        .resource_class = .IN,
        .ttl = 16777472,
        .data = RecordData{
            .ip = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 0),
        },
    };
    try record0.writeTo(&writer);

    const record1 = Record{
        .name = "example_1.com",
        .resource_type = .AAAA,
        .resource_class = .IN,
        .ttl = 16777472,
        .data = RecordData{
            .ip = std.net.Address.initIp6([16]u8{ 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, 0, 0, 0),
        },
    };
    try record1.writeTo(&writer);

    const written = writer.buffered();
    var reader = std.Io.Reader.fixed(written);

    var message_reader = try MessageReader.init(&reader);

    try std.testing.expectEqual(header, message_reader.header);

    const read_question = (try message_reader.nextQuestion()).?;
    try std.testing.expectEqualStrings(question.name, read_question.name);
    try std.testing.expectEqual(question.resource_class, read_question.resource_class);
    try std.testing.expectEqual(question.resource_type, read_question.resource_type);

    const read_record0 = (try message_reader.nextRecord()).?;
    try std.testing.expectEqualStrings(record0.name, read_record0.name);
    try std.testing.expectEqual(record0.ttl, read_record0.ttl);
    try std.testing.expectEqual(record0.resource_class, read_record0.resource_class);
    try std.testing.expectEqual(record0.resource_type, read_record0.resource_type);
    try std.testing.expect(record0.data.ip.eql(read_record0.data.ip));

    const read_record1 = (try message_reader.nextRecord()).?;
    try std.testing.expectEqualStrings(record1.name, read_record1.name);
    try std.testing.expectEqual(record1.ttl, read_record1.ttl);
    try std.testing.expectEqual(record1.resource_class, read_record1.resource_class);
    try std.testing.expectEqual(record1.resource_type, read_record1.resource_type);
    try std.testing.expect(record1.data.ip.eql(read_record1.data.ip));
}
