#![warn(rust_2018_idioms)]

use std::hash::Hasher;

use arrayvec::ArrayVec;

struct XXHash32 {
    acc: [u32; 4],
    seed: u32,
    total_length: usize,
    unprocessed_bytes: ArrayVec<u8, 16>,
}

impl XXHash32 {
    const PRIME32_1: u32 = 0x9E3779B1u32;
    const PRIME32_2: u32 = 0x85EBCA77u32;
    const PRIME32_3: u32 = 0xC2B2AE3Du32;
    const PRIME32_4: u32 = 0x27D4EB2Fu32;
    const PRIME32_5: u32 = 0x165667B1u32;

    fn new(seed: u32) -> Self {
        Self {
            acc: [
                seed.wrapping_add(Self::PRIME32_1.wrapping_add(Self::PRIME32_2)),
                seed.wrapping_add(Self::PRIME32_2),
                seed,
                seed.wrapping_sub(Self::PRIME32_1),
            ],
            seed,
            total_length: 0,
            unprocessed_bytes: ArrayVec::new(),
        }
    }

    fn process_stripe(&mut self, bytes: &[u8]) {
        let lane_iter = bytes.chunks_exact(4);

        for (index, lane) in lane_iter.enumerate() {
            let lane = u32::from_le_bytes(lane.try_into().expect("4 bytes"));
            self.acc[index] = self.acc[index].wrapping_add(lane.wrapping_mul(Self::PRIME32_2));
            self.acc[index] = self.acc[index].rotate_left(13);
            self.acc[index] = self.acc[index].wrapping_mul(Self::PRIME32_1);
        }
    }
}

impl Default for XXHash32 {
    fn default() -> Self {
        Self::new(0)
    }
}

impl Hasher for XXHash32 {
    fn finish(&self) -> u64 {
        // accumulator convergence
        let mut acc = if self.total_length < 16 {
            // special case: input is less than 16 bytes
            self.seed.wrapping_add(Self::PRIME32_5)
        } else {
            self.acc[0]
                .rotate_left(1)
                .wrapping_add(self.acc[1].rotate_left(7))
                .wrapping_add(self.acc[2].rotate_left(12))
                .wrapping_add(self.acc[3].rotate_left(18))
        };

        // add input length
        acc += self.total_length as u32;

        // consume remaining input
        let mut chunk_iter = self.unprocessed_bytes.as_slice().chunks_exact(4);

        for chunk in chunk_iter.by_ref() {
            let lane = u32::from_le_bytes(chunk.try_into().expect("4 bytes"));
            acc = acc.wrapping_add(lane.wrapping_mul(Self::PRIME32_3));
            acc = acc.rotate_left(17).wrapping_mul(Self::PRIME32_4);
        }

        let mut chunk_iter_single_byte = chunk_iter.remainder().chunks_exact(1);

        for chunk in chunk_iter_single_byte.by_ref() {
            let lane = u8::from_le(chunk[0]) as u32;
            acc = acc.wrapping_add(lane.wrapping_mul(Self::PRIME32_5));
            acc = acc.rotate_left(11).wrapping_mul(Self::PRIME32_1);
        }

        // final mix (avalanche)
        acc ^= acc >> 15;
        acc = acc.wrapping_mul(Self::PRIME32_2);
        acc ^= acc >> 13;
        acc = acc.wrapping_mul(Self::PRIME32_3);
        acc ^= acc >> 16;

        acc as u64
    }

    fn write(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }

        // process stripes

        self.total_length += bytes.len();

        // process incomplete stripe from last time
        let remaining_capacity = self.unprocessed_bytes.remaining_capacity();
        let mut bytes_copied = 0;
        if !self.unprocessed_bytes.is_empty() && remaining_capacity > 0 {
            let bytes_to_copy = bytes.len().min(remaining_capacity);
            self.unprocessed_bytes
                .try_extend_from_slice(&bytes[0..bytes_to_copy])
                .expect("remaining capacity must be sufficient");

            bytes_copied = bytes_to_copy;
            self.unprocessed_bytes.is_full();

            if self.unprocessed_bytes.is_full() {
                let unprocessed_bytes_stripe: ArrayVec<_, 16> = self
                    .unprocessed_bytes
                    .drain(0..self.unprocessed_bytes.len())
                    .collect();
                self.process_stripe(&unprocessed_bytes_stripe);
            } else {
                return;
            }
        }

        assert_eq!(self.unprocessed_bytes.len(), 0);

        // process remaining bytes, if there are any

        if bytes.len() > bytes_copied {
            let mut chunk_iter = bytes[bytes_copied..].chunks_exact(16);

            for chunk in chunk_iter.by_ref() {
                self.process_stripe(chunk);
            }

            // put remaining incomplete stripe to unprocessed_bytes
            // for next call to write or finish
            self.unprocessed_bytes
                .try_extend_from_slice(chunk_iter.remainder())
                .expect("must fit into self.unprocessed_bytes");
        }
    }
}

struct XXHash64 {
    acc: [u64; 4],
    seed: u64,
    total_length: usize,
    unprocessed_bytes: ArrayVec<u8, 32>,
}

impl XXHash64 {
    const PRIME64_1: u64 = 0x9E3779B185EBCA87u64;
    const PRIME64_2: u64 = 0xC2B2AE3D27D4EB4Fu64;
    const PRIME64_3: u64 = 0x165667B19E3779F9u64;
    const PRIME64_4: u64 = 0x85EBCA77C2B2AE63u64;
    const PRIME64_5: u64 = 0x27D4EB2F165667C5u64;

    fn new(seed: u64) -> Self {
        Self {
            acc: [
                seed.wrapping_add(Self::PRIME64_1)
                    .wrapping_add(Self::PRIME64_2),
                seed.wrapping_add(Self::PRIME64_2),
                seed,
                seed.wrapping_sub(Self::PRIME64_1),
            ],
            seed,
            total_length: 0,
            unprocessed_bytes: ArrayVec::new(),
        }
    }

    fn round(acc: u64, lane: u64) -> u64 {
        acc.wrapping_add(lane.wrapping_mul(Self::PRIME64_2))
            .rotate_left(31)
            .wrapping_mul(Self::PRIME64_1)
    }

    fn process_stripe(&mut self, bytes: &[u8]) {
        let lane_iter = bytes.chunks_exact(8);

        for (index, lane) in lane_iter.enumerate() {
            let lane = u64::from_le_bytes(lane.try_into().expect("8 bytes"));
            // self.acc[index] = self.acc[index].wrapping_add(lane.wrapping_mul(Self::PRIME64_2));
            // self.acc[index] = self.acc[index].rotate_left(31);
            // self.acc[index] = self.acc[index].wrapping_mul(Self::PRIME64_1);
            self.acc[index] = Self::round(self.acc[index], lane);
        }
    }
}

impl Default for XXHash64 {
    fn default() -> Self {
        Self::new(0)
    }
}

impl Hasher for XXHash64 {
    fn finish(&self) -> u64 {
        let mut acc = if self.total_length < 32 {
            // special case: input is less than 32 bytes
            self.seed.wrapping_add(Self::PRIME64_5)
        } else {
            let mut converged_acc = self.acc[0]
                .rotate_left(1)
                .wrapping_add(self.acc[1].rotate_left(7))
                .wrapping_add(self.acc[2].rotate_left(12))
                .wrapping_add(self.acc[3].rotate_left(18));

            for acc in self.acc {
                converged_acc ^= Self::round(0, acc);
                converged_acc = converged_acc
                    .wrapping_mul(Self::PRIME64_1)
                    .wrapping_add(Self::PRIME64_4);
            }

            converged_acc
        };

        acc += self.total_length as u64;

        // consume remaining input
        let mut chunk_iter = self.unprocessed_bytes.as_slice().chunks_exact(8);

        for chunk in chunk_iter.by_ref() {
            let lane = u64::from_le_bytes(chunk.try_into().expect("8 bytes"));
            acc ^= Self::round(0, lane);
            acc = acc.rotate_left(27).wrapping_mul(Self::PRIME64_1);
            acc = acc.wrapping_add(Self::PRIME64_4);
        }

        let mut chunk_iter_four_bytes = chunk_iter.remainder().chunks_exact(4);

        for chunk in chunk_iter_four_bytes.by_ref() {
            let lane = u32::from_le_bytes(chunk.try_into().expect("4 bytes")) as u64;
            acc ^= lane.wrapping_mul(Self::PRIME64_1);
            acc = acc.rotate_left(23).wrapping_mul(Self::PRIME64_2);
            acc = acc.wrapping_add(Self::PRIME64_3);
        }

        let chunk_iter_single_byte = chunk_iter_four_bytes.remainder().chunks_exact(1);

        for chunk in chunk_iter_single_byte {
            let lane = u8::from_le(chunk[0]) as u64;
            acc ^= lane.wrapping_mul(Self::PRIME64_5);
            acc = acc.rotate_left(11).wrapping_mul(Self::PRIME64_1);
        }

        // final mix (avalanche)
        acc ^= acc >> 33;
        acc = acc.wrapping_mul(Self::PRIME64_2);
        acc ^= acc >> 29;
        acc = acc.wrapping_mul(Self::PRIME64_3);
        acc ^= acc >> 32;

        acc
    }

    fn write(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }

        self.total_length += bytes.len();

        // process incomplete stripe from last time
        let remaining_capacity = self.unprocessed_bytes.remaining_capacity();
        let mut bytes_copied = 0;
        if !self.unprocessed_bytes.is_empty() && remaining_capacity > 0 {
            let bytes_to_copy = bytes.len().min(remaining_capacity);
            self.unprocessed_bytes
                .try_extend_from_slice(&bytes[0..bytes_to_copy])
                .expect("remaining capacity must be sufficient");

            bytes_copied = bytes_to_copy;
            self.unprocessed_bytes.is_full();

            if self.unprocessed_bytes.is_full() {
                let unprocessed_bytes_stripe: ArrayVec<_, 32> = self
                    .unprocessed_bytes
                    .drain(0..self.unprocessed_bytes.len())
                    .collect();
                self.process_stripe(&unprocessed_bytes_stripe);
            } else {
                return;
            }
        }

        assert_eq!(self.unprocessed_bytes.len(), 0);

        // process remaining bytes, if there are any

        if bytes.len() > bytes_copied {
            let mut chunk_iter = bytes[bytes_copied..].chunks_exact(32);

            for chunk in chunk_iter.by_ref() {
                self.process_stripe(chunk);
            }

            // put remaining incomplete stripe to unprocessed_bytes
            // for next call to write or finish
            self.unprocessed_bytes
                .try_extend_from_slice(chunk_iter.remainder())
                .expect("must fit into self.unprocessed_bytes");
        }
    }
}

struct XXHash<S> {
    acc: [S; 4],
}

impl XXHash<u32> {}
impl XXHash<u64> {}

#[cfg(test)]
mod tests {
    use std::hash::Hasher;

    use rstest::rstest;

    use super::{XXHash32, XXHash64};

    #[rstest]
    #[case(&[], 0x02CC5D05u64)]
    #[case(&b"xy"[..], 0x548c8872u64)]
    #[case(&b"abcd"[..], 0xa3643705u64)]
    #[case(&b"abcdefghijklmnop"[..], 0x9d2d8b62u64)]
    fn test_xxhash32(#[case] input: &[u8], #[case] expected: u64) {
        let mut xxhash = XXHash32::default();

        xxhash.write(&input);

        assert_eq!(xxhash.finish(), expected);
    }

    #[test]
    fn test_xxhash32_one_byte_at_a_time() {
        let mut xxhash = XXHash32::default();

        let input = &b"abcdefghijklmnop"[..];
        assert_eq!(input.len(), 16);
        for x in input {
            xxhash.write_u8(*x);
        }

        assert_eq!(xxhash.finish(), 0x9d2d8b62u64);
    }

    #[test]
    fn test_xxhash32_full_stride_followed_by_incomplete_one() {
        let mut xxhash = XXHash32::default();

        let input = &b"abcdefghijklmnop"[..];
        assert_eq!(input.len(), 16);
        xxhash.write(input);

        let input = &b"q"[..];
        xxhash.write(input);

        assert_eq!(xxhash.finish(), 0xb3b873e1u64);
    }

    #[rstest]
    #[case(&[], 0xef46db3751d8e999u64)]
    #[case(&b"xy"[..], 0xd636cdd32ee68a9fu64)]
    #[case(&b"abcd"[..], 0xde0327b0d25d92ccu64)]
    #[case(&b"abcdefghijklmnop"[..], 0x71ce8137ca2dd53du64)]
    // #[ignore = "not implemented yet"]
    fn test_xxhash64(#[case] input: &[u8], #[case] expected: u64) {
        let mut xxhash = XXHash64::default();

        xxhash.write(&input);

        assert_eq!(xxhash.finish(), expected);
    }

    #[test]
    fn test_xxhash64_one_byte_at_a_time() {
        let mut xxhash = XXHash64::default();

        let input = &b"abcdefghijklmnop"[..];
        assert_eq!(input.len(), 16);
        for x in input {
            xxhash.write_u8(*x);
        }

        assert_eq!(xxhash.finish(), 0x71ce8137ca2dd53du64);
    }

    #[test]
    fn test_xxhash64_full_stride_followed_by_incomplete_one() {
        let mut xxhash = XXHash64::default();

        let input = &b"abcdefghijklmnopabcdefghijklmnop"[..];
        assert_eq!(input.len(), 32);
        xxhash.write(input);

        let input = &b"q"[..];
        xxhash.write(input);

        assert_eq!(xxhash.finish(), 0x85510cf15f44b71eu64);
    }
}
