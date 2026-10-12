//! Implements Binary Fuse filters.
// Port of https://github.com/FastFilter/xorfilter/blob/master/binaryfusefilter.go

use alloc::vec::Vec;
use core::convert::TryInto;

use libm::{floor, fmax, log};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[inline]
pub fn segment_length(arity: u32, size: u32) -> u32 {
    if size == 0 {
        return 4;
    }

    match arity {
        3 => 1 << (floor(log(size as f64) / log(3.33_f64) + 2.25) as u32),
        4 => 1 << (floor(log(size as f64) / log(2.91_f64) - 0.5) as u32),
        _ => 65536,
    }
}

#[inline]
pub fn size_factor(arity: u32, size: u32) -> f64 {
    match arity {
        3 => fmax(
            1.125_f64,
            0.875 + 0.25 * log(1000000_f64) / log(size as f64),
        ),
        4 => fmax(1.075_f64, 0.77 + 0.305 * log(600000_f64) / log(size as f64)),
        _ => 2.0,
    }
}

#[inline]
pub const fn hash_of_hash(
    hash: u64,
    segment_length: u32,
    segment_length_mask: u32,
    segment_count_length: u32,
) -> (u32, u32, u32) {
    let hi = ((hash as u128 * segment_count_length as u128) >> 64) as u64;
    let h0 = hi as u32;
    let mut h1 = h0 + segment_length;
    let mut h2 = h1 + segment_length;
    h1 ^= ((hash >> 18) as u32) & segment_length_mask;
    h2 ^= (hash as u32) & segment_length_mask;
    (h0, h1, h2)
}

#[inline]
pub const fn mod3(x: u8) -> u8 {
    if x > 2 { x - 3 } else { x }
}

/// Descriptor for a binary fuse filter.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    /// The seed used for hashing keys into the filter.
    pub seed: u64,
    /// The length of each segment in the filter.
    pub segment_length: u32,
    /// A mask used for segment length calculations.
    pub segment_length_mask: u32,
    /// The total length of all segments combined.
    pub segment_count_length: u32,
}

impl Descriptor {
    /// Length of the descriptor when serialized with [`DmaSerializable`](crate::DmaSerializable).
    pub const DMA_LEN: usize = u64::BITS as usize / 8 + (u32::BITS as usize / 8) * 3;

    /// The descriptor of a filter cut into `segment_count` segments of `segment_length`
    /// fingerprints, hashed with `seed`: the mask and the length of the segments are derived.
    ///
    /// `None` unless `segment_length` is a power of two and a filter of that many segments
    /// is no longer than `u32::MAX` fingerprints.
    pub const fn new(seed: u64, segment_length: u32, segment_count: u32) -> Option<Self> {
        if !segment_length.is_power_of_two() {
            return None;
        }
        let Some(segment_count_length) = segment_count.checked_mul(segment_length) else {
            return None;
        };
        let descriptor = Self {
            seed,
            segment_length,
            segment_length_mask: segment_length - 1,
            segment_count_length,
        };
        if descriptor.fingerprints_len() > u32::MAX as usize {
            return None;
        }
        Some(descriptor)
    }

    /// The number of segments a key's first slot can fall in.
    ///
    /// A key has one slot in each of three consecutive segments, so the filter holds two more.
    pub const fn segment_count(&self) -> u32 {
        match self.segment_count_length.checked_div(self.segment_length) {
            Some(count) => count,
            None => 0,
        }
    }

    /// The number of fingerprints a filter with this descriptor has.
    pub const fn fingerprints_len(&self) -> usize {
        self.segment_count_length as usize + 2 * self.segment_length as usize
    }

    /// Whether a lookup with this descriptor stays inside `len` fingerprints: the segments are a
    /// power of two long, their mask and count agree, and they fit.
    pub const fn fits(&self, len: usize) -> bool {
        // `&` and not `&&`: every term is a compare of registers, and one branch is cheaper to
        // predict than six (this runs on every lookup that opens a filter from a blob)
        let end = self.segment_count_length as u64 + 2 * self.segment_length as u64;
        self.segment_length.is_power_of_two()
            & (self.segment_length_mask == self.segment_length.wrapping_sub(1))
            & (self.segment_count_length & self.segment_length_mask == 0)
            & (end <= u32::MAX as u64)
            & (end <= len as u64)
    }
}

#[inline]
pub fn parse_bfuse_descriptor(descriptor: &[u8]) -> Descriptor {
    Descriptor {
        seed: u64::from_le_bytes(descriptor[0..8].try_into().unwrap()),
        segment_length: u32::from_le_bytes(descriptor[8..12].try_into().unwrap()),
        segment_length_mask: u32::from_le_bytes(descriptor[12..16].try_into().unwrap()),
        segment_count_length: u32::from_le_bytes(descriptor[16..20].try_into().unwrap()),
    }
}

#[inline]
pub fn serialize_bfuse_descriptor(descriptor: &Descriptor, out: &mut [u8]) {
    out[0..8].copy_from_slice(&descriptor.seed.to_le_bytes());
    out[8..12].copy_from_slice(&descriptor.segment_length.to_le_bytes());
    out[12..16].copy_from_slice(&descriptor.segment_length_mask.to_le_bytes());
    out[16..20].copy_from_slice(&descriptor.segment_count_length.to_le_bytes());
}

/// A fingerprint type of a binary fuse filter: the low bits of `hash ^ (hash >> 32)`.
pub trait Fingerprint: Copy + Default + core::ops::BitXor<Output = Self> {
    /// The fingerprint of a key's hash.
    fn of_hash(hash: u64) -> Self;
}

macro_rules! impl_fingerprint {
    ($($t:ty),*) => {$(
        impl Fingerprint for $t {
            #[inline]
            fn of_hash(hash: u64) -> Self {
                (hash ^ (hash >> 32)) as $t
            }
        }
    )*};
}
impl_fingerprint!(u8, u16, u32);

/// The message of the error [`construct`] returns when a key appears twice. The filter
/// constructors (`bfuse_from_impl`) catch it, deduplicate the keys and build again, so callers
/// of `BinaryFuse8/16/32` never see it.
pub const DUPLICATE_KEYS: &str =
    "Binary Fuse filters must be constructed from a collection containing all distinct keys.";

/// The segment layout of a filter of `size` keys, before any retry changes it.
struct Layout {
    segment_length: u32,
    segment_count: u32,
    /// Fingerprints in the filter: `(segment_count + 2) * segment_length`.
    fp_len: usize,
}

fn layout(size: usize) -> Layout {
    let arity = 3u32;
    let segment_length: u32 = segment_length(arity, size as u32).min(262144);
    let size_factor: f64 = size_factor(arity, size as u32);
    let capacity: u32 = if size > 1 {
        libm::round(size as f64 * size_factor) as u32
    } else {
        0
    };
    let init_segment_count = capacity.div_ceil(segment_length);
    let array_len = init_segment_count * segment_length;
    let segment_count: u32 = {
        let proposed = array_len.div_ceil(segment_length);
        if proposed < arity {
            1
        } else {
            proposed - (arity - 1)
        }
    };
    let fp_len = ((segment_count + arity - 1) * segment_length) as usize;
    Layout {
        segment_length,
        segment_count,
        fp_len,
    }
}

/// How many fingerprints a filter of `size` keys has.
pub fn fingerprints_len(size: usize) -> usize {
    layout(size).fp_len
}

/// Scratch space of a binary fuse construction, kept between builds so that building many
/// filters does not allocate (and zero fresh pages for) the same arrays every time.
#[derive(Default)]
pub struct BinaryFuseScratch {
    alone: Vec<u32>,
    t2count: Vec<u8>,
    t2hash: Vec<u64>,
    reverse_h: Vec<u8>,
    reverse_order: Vec<u64>,
    start_pos: Vec<usize>,
}

/// Scratch above this many bytes is freed after the build that grew it. A build of 1.4 million
/// keys holds 32 MiB; one thread that built a 5-million-key shard would otherwise hold 120 MiB
/// to build filters of a hundred keys, and the large builds are the ones whose cost the
/// allocation is the smallest share of.
const KEEP_BYTES: usize = 32 << 20;

impl BinaryFuseScratch {
    /// Frees the arrays when they are larger than [`KEEP_BYTES`].
    pub(crate) fn trim(&mut self) {
        if self.bytes() > KEEP_BYTES {
            *self = Self::default();
        }
    }

    /// Bytes held between builds.
    pub fn bytes(&self) -> usize {
        self.alone.capacity() * 4
            + self.t2count.capacity()
            + self.t2hash.capacity() * 8
            + self.reverse_h.capacity()
            + self.reverse_order.capacity() * 8
            + self.start_pos.capacity() * 8
    }
}

/// Builds the fingerprints of a binary fuse filter of the distinct `keys` into `fingerprints`
/// (`fingerprints_len(keys.len())` of them, zeroed or random), and returns the descriptor.
///
/// This is Graf and Lemire's construction as `xorf` 0.13 ran it, step for step: the same seed
/// sequence, the same retries, the same peeling order, so with zeroed `fingerprints` the result
/// is byte for byte what 0.13 built.
pub fn construct<F, I>(
    scratch: &mut BinaryFuseScratch,
    keys: I,
    fingerprints: &mut [F],
    max_iter: u32,
) -> Result<Descriptor, &'static str>
where
    F: Fingerprint,
    I: ExactSizeIterator<Item = u64> + Clone,
{
    use crate::{prelude::mix, splitmix64::splitmix64};
    let size: usize = keys.len();
    let Layout {
        mut segment_length,
        mut segment_count,
        fp_len,
    } = layout(size);
    debug_assert_eq!(fingerprints.len(), fp_len);
    let mut segment_length_mask: u32 = segment_length - 1;
    let mut segment_count_length = segment_count * segment_length;

    let mut rng = 1;
    let mut seed = splitmix64(&mut rng);
    let capacity = fp_len;
    let BinaryFuseScratch {
        alone,
        t2count,
        t2hash,
        reverse_h,
        reverse_order,
        start_pos,
    } = scratch;
    // `alone` and `reverse_h` are written before they are read; the others start at zero
    if alone.len() < capacity {
        alone.resize(capacity, 0);
    }
    if reverse_h.len() < size {
        reverse_h.resize(size, 0);
    }
    t2count.clear();
    t2count.resize(capacity, 0);
    t2hash.clear();
    t2hash.resize(capacity, 0);
    reverse_order.clear();
    reverse_order.resize(size + 1, 0);
    reverse_order[size] = 1;
    let (alone, t2count, t2hash) = (&mut alone[..capacity], &mut t2count[..], &mut t2hash[..]);
    let (reverse_h, reverse_order) = (&mut reverse_h[..size], &mut reverse_order[..]);

    // The empirical segment-length formula is too large just after a
    // power-of-two step, so peeling rarely succeeds. Every fourth try
    // keeps the same capacity and uses the previous (halved) length:
    // https://github.com/FastFilter/xorfilter/pull/50
    let try_smaller_segment = size > 4 && size < 1_000_000;
    let start_pos_cap = {
        let max_segment_count = if try_smaller_segment {
            segment_count.saturating_mul(2).saturating_add(2)
        } else {
            segment_count
        };
        let mut block_bits = 1;
        while (1 << block_bits) < max_segment_count {
            block_bits += 1;
        }
        1usize << block_bits
    };
    if start_pos.len() < start_pos_cap {
        start_pos.resize(start_pos_cap, 0);
    }
    let start_pos = &mut start_pos[..start_pos_cap];
    let mut h012: [u32; 6] = [0; 6];
    let mut done = false;
    let mut ultimate_size = 0;
    for iter in 0..max_iter {
        let iteration = iter + 1;
        if try_smaller_segment {
            match iteration % 4 {
                // Same fingerprint array, recut into more, shorter segments.
                2 => {
                    segment_length /= 2;
                    segment_length_mask = segment_length - 1;
                    segment_count = segment_count * 2 + 2;
                    segment_count_length = segment_count * segment_length;
                }
                3 => {
                    // Restore the formula layout.
                    segment_length *= 2;
                    segment_length_mask = segment_length - 1;
                    segment_count = segment_count / 2 - 1;
                    segment_count_length = segment_count * segment_length;
                }
                _ => {}
            }
        }

        let block_bits = {
            let mut block_bits = 1;
            while (1 << block_bits) < segment_count {
                block_bits += 1;
            }
            block_bits
        };
        let start_pos_len: usize = 1 << block_bits;
        for (i, pos) in start_pos[..start_pos_len].iter_mut().enumerate() {
            *pos = (((i as u64) * (size as u64)) >> block_bits) as usize;
        }
        for key in keys.clone() {
            let hash = mix(key, seed);
            let mut segment_index = hash >> (64 - block_bits);
            while reverse_order[start_pos[segment_index as usize]] != 0 {
                segment_index += 1;
                segment_index &= (1 << block_bits) - 1;
            }
            reverse_order[start_pos[segment_index as usize]] = hash;
            start_pos[segment_index as usize] += 1;
        }

        let mut error = false;
        let mut duplicates = 0;
        for &hash in &reverse_order[..size] {
            let (index1, index2, index3) = hash_of_hash(
                hash,
                segment_length,
                segment_length_mask,
                segment_count_length,
            );
            let (index1, index2, index3) = (index1 as usize, index2 as usize, index3 as usize);
            t2count[index1] += 4;
            // t2count[index1] ^= 0; NOOP
            t2hash[index1] ^= hash;
            t2count[index2] += 4;
            t2count[index2] ^= 1;
            t2hash[index2] ^= hash;
            t2count[index3] += 4;
            t2count[index3] ^= 2;
            t2hash[index3] ^= hash;

            if t2hash[index1] & t2hash[index2] & t2hash[index3] == 0
                && (((t2hash[index1] == 0) && (t2count[index1] == 8))
                    || ((t2hash[index2] == 0) && (t2count[index2] == 8))
                    || ((t2hash[index3] == 0) && (t2count[index3] == 8)))
            {
                duplicates += 1;
                t2count[index1] -= 4;
                // t2count[index1] ^= 0; NOOP
                t2hash[index1] ^= hash;
                t2count[index2] -= 4;
                t2count[index2] ^= 1;
                t2hash[index2] ^= hash;
                t2count[index3] -= 4;
                t2count[index3] ^= 2;
                t2hash[index3] ^= hash;
            }
            error = t2count[index1] < 4 || t2count[index2] < 4 || t2count[index3] < 4;
        }
        if error {
            reverse_order[..size].fill(0);
            t2count.fill(0);
            t2hash.fill(0);
            seed = splitmix64(&mut rng);
            continue;
        }

        // Key addition complete. Perform enqueing.

        let mut qsize = 0;
        for (i, &count) in t2count.iter().enumerate() {
            alone[qsize] = i as u32;
            if (count >> 2) == 1 {
                qsize += 1;
            }
        }
        let mut stack_size = 0;
        while qsize > 0 {
            qsize -= 1;
            let index = alone[qsize] as usize;
            if (t2count[index] >> 2) == 1 {
                let hash = t2hash[index];
                let found: u8 = t2count[index] & 3;
                reverse_h[stack_size] = found;
                reverse_order[stack_size] = hash;
                stack_size += 1;

                let (index1, index2, index3) = hash_of_hash(
                    hash,
                    segment_length,
                    segment_length_mask,
                    segment_count_length,
                );

                h012[1] = index2;
                h012[2] = index3;
                h012[3] = index1;
                h012[4] = h012[1];

                let other_index1 = h012[(found + 1) as usize] as usize;
                alone[qsize] = other_index1 as u32;
                if (t2count[other_index1] >> 2) == 2 {
                    qsize += 1;
                }
                t2count[other_index1] -= 4;
                t2count[other_index1] ^= mod3(found + 1);
                t2hash[other_index1] ^= hash;

                let other_index2 = h012[(found + 2) as usize] as usize;
                alone[qsize] = other_index2 as u32;
                if (t2count[other_index2] >> 2) == 2 {
                    qsize += 1;
                }
                t2count[other_index2] -= 4;
                t2count[other_index2] ^= mod3(found + 2);
                t2hash[other_index2] ^= hash;
            }
        }

        if stack_size + duplicates == size {
            ultimate_size = stack_size;
            done = true;
            break;
        }

        // Filter failed to be created; reset for a retry.
        reverse_order[..size].fill(0);
        t2count.fill(0);
        t2hash.fill(0);
        seed = splitmix64(&mut rng);

        // Peeling a set with a repeated key fails at every seed (both copies land in the same
        // slots whatever the seed), and the other retries are whole builds: 0.13 spent 4.5 s on
        // 100,000 keys and 100 repeats before giving up. Honest failures are rare (a try in fifty
        // for a handful of keys, none in 20,000 filters of 30,000 keys needed a fifth), so
        // after the eighth, look for the repeat. The fingerprint array is sized for `keys.len()`
        // by the caller, so a build of the deduplicated keys is the caller's to make.
        if iteration == 8 {
            let mut sorted: Vec<u64> = keys.clone().collect();
            sorted.sort_unstable();
            if sorted.windows(2).any(|w| w[0] == w[1]) {
                return Err(DUPLICATE_KEYS);
            }
        }
    }
    if !done {
        return Err("Failed to construct binary fuse filter.");
    }

    // Construct all fingerprints
    let size = ultimate_size;
    for i in (0..size).rev() {
        let hash = reverse_order[i];
        let xor2 = F::of_hash(hash);
        let (index1, index2, index3) = hash_of_hash(
            hash,
            segment_length,
            segment_length_mask,
            segment_count_length,
        );
        let found = reverse_h[i] as usize;
        h012[0] = index1;
        h012[1] = index2;
        h012[2] = index3;
        h012[3] = h012[0];
        h012[4] = h012[1];
        fingerprints[h012[found] as usize] =
            xor2 ^ fingerprints[h012[found + 1] as usize] ^ fingerprints[h012[found + 2] as usize];
    }

    Ok(Descriptor {
        seed,
        segment_length,
        segment_length_mask,
        segment_count_length,
    })
}

/// Implements `try_from(&[u64])` for an binary fuse filter of fingerprint type `$fpty`.
#[doc(hidden)]
#[macro_export]
macro_rules! bfuse_from_impl(
    ($keys:ident fingerprint $fpty:ty, max iter $max_iter:expr, scratch $scratch:expr) => {
        {
            #[allow(unused_imports)]
            use $crate::make_block;
            use $crate::{
                make_fp_block,
                prelude::bfuse::{construct, fingerprints_len, DUPLICATE_KEYS},
            };

            #[cfg(debug_assertions)] {
                use $crate::prelude::all_distinct;
                debug_assert!(all_distinct($keys.clone()), "Binary Fuse filters must be constructed from a collection containing all distinct keys.");
            }

            let fp_array_len = fingerprints_len($keys.len());
            let mut fingerprints: Box<[$fpty]> = make_fp_block!(fp_array_len);
            let mut built = construct($scratch, $keys.clone(), &mut fingerprints, $max_iter);
            if built == Err(DUPLICATE_KEYS) {
                // A repeated key can never peel. Build from the distinct keys instead; the
                // filter then contains every key, which is what the caller meant.
                let mut distinct: Vec<u64> = $keys.collect();
                distinct.sort_unstable();
                distinct.dedup();
                let fp_array_len = fingerprints_len(distinct.len());
                fingerprints = make_fp_block!(fp_array_len);
                built = construct($scratch, distinct.iter().copied(), &mut fingerprints, $max_iter);
            }
            $scratch.trim();
            let descriptor = built?;
            Ok(Self { descriptor, fingerprints })
        }
    };
);

/// Implements `contains(u64)` for a binary fuse filter of fingerprint type `$fpty`.
#[doc(hidden)]
#[macro_export]
macro_rules! bfuse_contains_impl(
    ($key:expr, $self:expr, fingerprint $fpty:ty) => {
        {
            use $crate::{
                fingerprint,
                prelude::{
                    mix,
                    bfuse::hash_of_hash
                },
            };
            let hash = mix($key, $self.descriptor.seed);
            let mut f = fingerprint!(hash) as $fpty;
            let (h0, h1, h2) = hash_of_hash(hash, $self.descriptor.segment_length, $self.descriptor.segment_length_mask, $self.descriptor.segment_count_length);
            f ^= $self.fingerprints[h0 as usize]
               ^ $self.fingerprints[h1 as usize]
               ^ $self.fingerprints[h2 as usize];
            f == 0
        }
    };
);

#[cfg(test)]
mod test {
    use super::*;
    use crate::splitmix64::splitmix64;

    /// A repeated key fails the peeling at every seed; `construct` has to say so after a few
    /// builds, not a thousand (which took 3.7 s for 100,000 keys and 100 repeats), and the
    /// constructors then build from the distinct keys.
    #[test]
    fn repeated_keys_fail_fast() {
        let mut state = 5;
        let mut keys: Vec<u64> = (0..20_000).map(|_| splitmix64(&mut state)).collect();
        for i in 0..200 {
            keys.push(keys[i * 7]);
        }
        // sorted, so the copies are far from each other in the bucket order the build uses
        keys.sort_unstable_by_key(|k| k.rotate_left(17));
        let mut fp = vec![0u8; fingerprints_len(keys.len())];
        let r = construct(
            &mut BinaryFuseScratch::default(),
            keys.iter().copied(),
            &mut fp,
            1_000,
        );
        assert_eq!(r.unwrap_err(), DUPLICATE_KEYS);
    }

    #[test]
    fn a_failure_that_is_not_a_repeat_is_still_retried() {
        // 11,515 keys fail every seed at the formula's segment length and are built at the
        // halved one (tests/boundary_size_construction.rs): a failed try is not a repeat
        let mut state = 28909;
        let keys: Vec<u64> = (0..11_515).map(|_| splitmix64(&mut state)).collect();
        let mut fp = vec![0u8; fingerprints_len(keys.len())];
        let d = construct(
            &mut BinaryFuseScratch::default(),
            keys.iter().copied(),
            &mut fp,
            1_000,
        )
        .unwrap();
        assert!(d.fits(fp.len()));
    }
}
