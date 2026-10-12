//! Filters built by xorf 0.13.0 (crates.io) read the same through this crate's view, and this
//! crate builds the filters 0.13.0 built: a file of filters written by one is read by the other.
//!
//! This is a crate of its own, outside the workspace, because a dev-dependency on 0.13.0 makes
//! `cargo -p xorf` ambiguous for the rest. Neither side has `uniform-random`, so the bytes of the
//! unused fingerprints are zero in both and the filters can be compared byte for byte.
//!
//!     cd compat && cargo test

use xorf::{BinaryFuse8, BinaryFuse8Ref, Descriptor, DmaSerializable, Filter, splitmix64};
use xorf013::{BinaryFuse8 as Old, DmaSerializable as OldDma, Filter as OldFilter};

fn keys(n: usize, state: u64) -> Vec<u64> {
    let mut s = state;
    (0..n).map(|_| splitmix64(&mut s)).collect()
}

/// What a sidecar stores for a filter: the descriptor, then the fingerprints.
fn blob_of_old(f: &Old) -> Vec<u8> {
    let mut b = vec![0u8; Old::DESCRIPTOR_LEN];
    f.dma_copy_descriptor_to(&mut b);
    b.extend_from_slice(f.dma_fingerprints());
    b
}

/// Sizes around every power of two the segment length changes at, the small ones, and the
/// one (11,515) that needs the halved segment length.
const SIZES: [usize; 24] = [
    0, 1, 2, 3, 4, 5, 6, 7, 10, 31, 100, 150, 1000, 1500, 4095, 4096, 4097, 11_515, 30_000, 65_535,
    65_536, 65_537, 200_000, 600_000,
];

#[test]
fn old_filters_read_through_the_view() {
    assert_eq!(Old::DESCRIPTOR_LEN, Descriptor::DMA_LEN);
    for (i, &n) in SIZES.iter().enumerate() {
        let ks = keys(n, i as u64 + 1);
        let old = Old::try_from(&ks).unwrap();
        let blob = blob_of_old(&old);
        let view = BinaryFuse8Ref::from_blob(&blob).unwrap();
        assert_eq!(view.len(), old.len(), "n={n}");
        assert!(
            ks.iter().all(|k| view.contains(k)),
            "n={n}: a key is missing"
        );
        // the same answer as 0.13 for keys that are not in it, false positives included
        let strangers = keys(100_000, 1 << 40 | i as u64);
        for s in &strangers {
            assert_eq!(view.contains(s), old.contains(s), "n={n}: stranger {s}");
        }
    }
}

#[test]
fn builds_what_0_13_built() {
    for (i, &n) in SIZES.iter().enumerate() {
        let ks = keys(n, i as u64 + 1);
        let old = blob_of_old(&Old::try_from(&ks).unwrap());
        let new = BinaryFuse8::try_from(&ks).unwrap();
        let mut blob = vec![0u8; BinaryFuse8::DESCRIPTOR_LEN];
        new.dma_copy_descriptor_to(&mut blob);
        blob.extend_from_slice(new.dma_fingerprints());
        assert!(
            blob == old,
            "n={n}: the filter differs from the one 0.13.0 builds"
        );
    }
}

/// One scratch for every build, in an order that leaves the largest arrays stale under the small
/// builds: still the bytes 0.13.0 builds.
#[test]
fn a_reused_scratch_builds_what_0_13_built() {
    let mut scratch = xorf::BinaryFuseScratch::default();
    for &n in SIZES.iter().rev().chain(SIZES.iter()) {
        let ks = keys(n, 99 + n as u64);
        let old = blob_of_old(&Old::try_from(&ks).unwrap());
        let new = BinaryFuse8::try_from_iterator_in(ks.iter().copied(), &mut scratch).unwrap();
        let mut blob = vec![0u8; BinaryFuse8::DESCRIPTOR_LEN];
        new.dma_copy_descriptor_to(&mut blob);
        blob.extend_from_slice(new.dma_fingerprints());
        assert!(blob == old, "n={n}: the filter differs from 0.13.0's");
    }
}
