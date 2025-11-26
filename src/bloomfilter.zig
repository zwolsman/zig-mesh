const std = @import("std");

pub fn BloomFilter(
    max_items: u64,
    fp_rate: f32,
) type {
    const m = calcM(max_items, fp_rate);
    const k = calcK(max_items, m);

    return struct {
        const Self = @This();
        pub const BitSet = std.bit_set.IntegerBitSet(m);
        bits: BitSet = .initEmpty(),
        m: u64 = m,
        k: u64 = k,

        pub fn load(mask: BitSet.MaskInt) Self {
            return .{
                .bits = .{
                    .mask = mask,
                },
            };
        }

        pub fn insert(self: *Self, item: []const u8) void {
            for (0..self.k) |i| {
                const idx = self.calcBitIdx(item, @truncate(i));
                self.bits.set(idx);
            }
        }

        pub fn contains(self: *const Self, item: []const u8) bool {
            var bit_set: usize = 0;

            for (0..self.k) |i| {
                const idx = self.calcBitIdx(item, @truncate(i));
                if (self.bits.isSet(idx)) {
                    bit_set += 1;
                }
            }

            return bit_set == self.k;
        }

        fn calcBitIdx(self: *const Self, item: []const u8, hash_seed: u32) u64 {
            const hash = std.hash.Murmur2_64.hashWithSeed(item, hash_seed);
            return hash % self.bits.capacity();
        }
    };
}

/// Calculate the appropriate number in bits of the Bloom filter, `m`, given
/// `n`, the expected number of elements contained in the Bloom filter and the
/// target false positive rate, `f`.
///
/// `(-nln(f))/ln(2)^2`
fn calcM(n: u64, f: f64) u64 {
    const numerator = @as(f64, @floatFromInt(n)) * -std.math.log(f64, std.math.e, f);
    const denominator = std.math.pow(f64, (std.math.log(f64, std.math.e, 2)), 2);
    return @intFromFloat(
        std.math.divTrunc(f64, numerator, denominator) catch unreachable,
    );
}

/// Calculate the number of hash functions to use, `k`, given `n` and `m`, the expected
/// number of elements contained in the Bloom filter and the size in bits of the Bloom
/// filter.
///
/// `(mln(2)/n)`
fn calcK(n: u64, m: u64) u64 {
    // https://en.wikipedia.org/wiki/Bloom_filter#Optimal_number_of_hash_functions
    const numerator = @as(f64, @floatFromInt(m)) * std.math.log(f64, std.math.e, 2);
    const denominator = @as(f64, @floatFromInt(n));
    return @as(u64, @intFromFloat(
        std.math.divTrunc(f64, numerator, denominator) catch unreachable,
    ));
}

test "Validate Bloomfilter" {
    std.testing.log_level = .debug;
    const Filter = BloomFilter(16, 0.01);
    var filter: Filter = .{};
    for (0..16) |i| {
        const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{@intCast(i)} ** 32);
        try std.testing.expect(!filter.contains(&kp.public_key.toBytes()));

        filter.insert(&kp.public_key.toBytes());

        try std.testing.expect(filter.contains(&kp.public_key.toBytes()));
    }

    const result = filter.bits.mask;
    std.log.debug("Bloomtfilter a mask: {d}", .{result});
    const filter_2: Filter = .load(result);
    for (0..16) |i| {
        const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{@intCast(i)} ** 32);
        try std.testing.expect(filter_2.contains(&kp.public_key.toBytes()));
    }
}

test "Transmit Bloomfilter" {
    std.testing.log_level = .debug;
    const Filter = BloomFilter(16, 0.005);
    var filter: Filter = .{};
    for (0..16) |i| {
        const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{@intCast(i)} ** 32);
        filter.insert(&kp.public_key.toBytes());
    }

    var out: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&out);
    var reader = std.Io.Reader.fixed(&out);

    try writer.writeInt(Filter.BitSet.MaskInt, filter.bits.mask, .big);

    std.log.debug("bytes written: {any} ({d})", .{ writer.buffered(), writer.end });

    const mask = try reader.takeInt(Filter.BitSet.MaskInt, .big);
    const f2: Filter = .load(mask);

    for (0..16) |i| {
        const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{@intCast(i)} ** 32);
        try std.testing.expect(f2.contains(&kp.public_key.toBytes()));
    }
}
