//! Binary Fuse construction from keys with repeats. Debug builds assert that keys are distinct,
//! so this runs under `cargo test --release`.
#![cfg(all(feature = "binary-fuse", not(debug_assertions)))]

use std::time::{Duration, Instant};
use xorf::{BinaryFuse8, BinaryFuse16, BinaryFuse32, Filter, splitmix64};

fn keys_with_repeats(n: usize, repeats: usize) -> Vec<u64> {
    let mut state = 7;
    let mut keys: Vec<u64> = (0..n).map(|_| splitmix64(&mut state)).collect();
    keys.extend_from_within(..repeats);
    keys
}

/// 0.13 built 10 or 20 repeats after a few retries and failed 100 after 4.5 s; every count must
/// now build, quickly, and contain every key.
#[test]
fn repeats_build_and_contain_every_key() {
    for repeats in [1, 5, 10, 20, 100] {
        let keys = keys_with_repeats(100_000, repeats);
        let start = Instant::now();
        let f8 = BinaryFuse8::try_from(&keys).unwrap();
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "{repeats} repeats took {:?}",
            start.elapsed()
        );
        let f16 = BinaryFuse16::try_from(&keys).unwrap();
        let f32 = BinaryFuse32::try_from(&keys).unwrap();
        for k in &keys {
            assert!(f8.contains(k) && f16.contains(k) && f32.contains(k));
        }
    }
}

/// The filter of repeats has the geometry (seed, segments) of the filter of the distinct keys.
#[test]
fn repeats_build_the_filter_of_the_distinct_keys() {
    let keys = keys_with_repeats(5_000, 50);
    let distinct = keys[..5_000].to_vec();
    let (a, b) = (
        BinaryFuse8::try_from(&keys).unwrap(),
        BinaryFuse8::try_from(&distinct).unwrap(),
    );
    assert_eq!(a.descriptor, b.descriptor);
    assert_eq!(a.fingerprints.len(), b.fingerprints.len());
}
