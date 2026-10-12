//! The borrowed view over a filter's bytes, the descriptor from its parts, and building in a kept scratch.
//! (That the view reads filters built by xorf 0.13.0 is `compat/`.)

use xorf::{BinaryFuse8, BinaryFuse8Ref, Descriptor, DmaSerializable, Filter, splitmix64};

fn keys(n: usize, state: u64) -> Vec<u64> {
    let mut s = state;
    (0..n).map(|_| splitmix64(&mut s)).collect()
}

/// Sizes around every power of two the segment length changes at, the small ones, and the
/// one (11,515) that needs the halved segment length.
const SIZES: [usize; 24] = [
    0, 1, 2, 3, 4, 5, 6, 7, 10, 31, 100, 150, 1000, 1500, 4095, 4096, 4097, 11_515, 30_000, 65_535,
    65_536, 65_537, 200_000, 600_000,
];

/// A view of an owned filter's bytes answers as the filter does, for every size.
#[test]
fn a_view_answers_as_its_filter_does() {
    for (i, &n) in SIZES.iter().enumerate() {
        let ks = keys(n, i as u64 + 1);
        let f = BinaryFuse8::try_from(&ks).unwrap();
        let mut blob = vec![0u8; BinaryFuse8::DESCRIPTOR_LEN];
        f.dma_copy_descriptor_to(&mut blob);
        blob.extend_from_slice(f.dma_fingerprints());
        let view = BinaryFuse8Ref::from_blob(&blob).unwrap();
        assert_eq!(view.len(), f.len(), "n={n}");
        assert_eq!(view.descriptor(), &f.descriptor, "n={n}");
        assert!(ks.iter().all(|k| view.contains(k)), "n={n}");
        let strangers = keys(20_000, 1 << 40 | i as u64);
        assert!(
            strangers.iter().all(|s| view.contains(s) == f.contains(s)),
            "n={n}"
        );
    }
}

/// Building in a kept scratch, after builds of other sizes, gives the same filter as a fresh one.
#[test]
fn a_reused_scratch_builds_the_same_filter() {
    let mut scratch = xorf::BinaryFuseScratch::default();
    // large then small then large, so stale bytes of every array would show
    for &n in SIZES.iter().chain(SIZES.iter().rev()) {
        let ks = keys(n, 7 + n as u64);
        let reused = BinaryFuse8::try_from_iterator_in(ks.iter().copied(), &mut scratch).unwrap();
        assert!(ks.iter().all(|k| reused.contains(k)), "n={n}");
        assert!(reused.descriptor.fits(reused.fingerprints.len()), "n={n}");
        assert_eq!(
            reused.fingerprints.len(),
            reused.descriptor.fingerprints_len(),
            "n={n}"
        );
        #[cfg(not(feature = "uniform-random"))]
        {
            let fresh = BinaryFuse8::try_from_iterator(ks.iter().copied()).unwrap();
            assert_eq!(reused.descriptor, fresh.descriptor, "n={n}");
            assert_eq!(reused.fingerprints, fresh.fingerprints, "n={n}");
        }
    }
    assert!(
        scratch.bytes() <= 32 << 20,
        "the scratch of a large build is not kept"
    );
}

#[test]
fn a_view_refuses_what_it_would_read_past() {
    let ks = keys(1000, 3);
    let f = BinaryFuse8::try_from(&ks).unwrap();
    let d = f.descriptor.clone();
    assert!(BinaryFuse8Ref::new(d.clone(), &f.fingerprints).is_ok());
    // fewer fingerprints than the descriptor says
    assert!(BinaryFuse8Ref::new(d.clone(), &f.fingerprints[1..]).is_err());
    assert!(BinaryFuse8Ref::new(d.clone(), &[]).is_err());
    // a segment length that is not a power of two, a mask that is not its own, a count that is not a multiple
    for bad in [
        Descriptor {
            segment_length: 1000,
            ..d.clone()
        },
        Descriptor {
            segment_length_mask: d.segment_length_mask >> 1,
            ..d.clone()
        },
        Descriptor {
            segment_count_length: d.segment_count_length + 1,
            ..d.clone()
        },
        Descriptor {
            segment_length: 0,
            segment_length_mask: u32::MAX,
            ..d.clone()
        },
        Descriptor {
            segment_count_length: u32::MAX - 1,
            ..d
        },
    ] {
        assert!(
            BinaryFuse8Ref::new(bad.clone(), &f.fingerprints).is_err(),
            "{bad:?}"
        );
    }
    // a blob shorter than its descriptor, and one cut short
    let mut blob = vec![0u8; BinaryFuse8::DESCRIPTOR_LEN];
    f.dma_copy_descriptor_to(&mut blob);
    assert!(BinaryFuse8Ref::from_blob(&blob[..10]).is_err());
    assert!(BinaryFuse8Ref::from_blob(&blob).is_err());
    blob.extend_from_slice(&f.fingerprints[..100]);
    assert!(BinaryFuse8Ref::from_blob(&blob).is_err());
    // whatever bytes there are, a view that opens never panics reading
    let mut junk = keys(64, 9)
        .iter()
        .flat_map(|k| k.to_le_bytes())
        .collect::<Vec<u8>>();
    for seg in [1u32, 2, 4, 1 << 10, 1 << 20] {
        junk[8..12].copy_from_slice(&seg.to_le_bytes());
        junk[12..16].copy_from_slice(&(seg - 1).to_le_bytes());
        junk[16..20].copy_from_slice(&(seg * 3).to_le_bytes());
        if let Ok(v) = BinaryFuse8Ref::from_blob(&junk) {
            for k in keys(1000, 5) {
                v.contains(&k);
            }
        }
    }
}

#[test]
fn a_descriptor_from_its_parts() {
    let ks = keys(5000, 11);
    let f = BinaryFuse8::try_from(&ks).unwrap();
    let d = &f.descriptor;
    let rebuilt = Descriptor::new(
        d.seed,
        d.segment_length,
        d.segment_count_length / d.segment_length,
    )
    .unwrap();
    assert_eq!(&rebuilt, d);
    assert_eq!(
        rebuilt.segment_count() * rebuilt.segment_length,
        rebuilt.segment_count_length
    );
    assert!(
        BinaryFuse8Ref::new(rebuilt, &f.fingerprints)
            .unwrap()
            .contains(&ks[0])
    );
    assert!(Descriptor::new(1, 1000, 3).is_none(), "not a power of two");
    assert!(
        Descriptor::new(1, 1 << 20, 1 << 12).is_none(),
        "longer than u32"
    );
    assert!(Descriptor::new(1, 1 << 20, u32::MAX).is_none(), "overflows");
}
