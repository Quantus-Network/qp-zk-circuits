use super::*;

#[test]
fn fri_layout_tracks_domains_and_rejects_invalid_resources() -> Result<()> {
    let layout = FriLayout::new(512, 4096, &[4, 4], 4, u64::MAX)?;
    assert_eq!(layout.rounds.len(), 2);
    assert_eq!(
        (
            layout.rounds[0].coefficients,
            layout.rounds[0].evaluations,
            layout.rounds[0].arity
        ),
        (512, 4096, 16)
    );
    assert_eq!(
        (
            layout.rounds[1].coefficients,
            layout.rounds[1].evaluations,
            layout.rounds[1].arity
        ),
        (32, 256, 16)
    );
    assert!(FriLayout::new(512, 4096, &[], 4, u64::MAX)?
        .rounds
        .is_empty());
    for (degree, rows, bits, cap, limit, expected) in [
        (3, 4096, vec![4], 4, u64::MAX, "invalid FRI input shape"),
        (512, 256, vec![4], 4, u64::MAX, "invalid FRI input shape"),
        (
            512,
            4096,
            vec![usize::MAX],
            4,
            u64::MAX,
            "FRI reduction arity overflow",
        ),
        (
            512,
            4096,
            vec![4, 6],
            4,
            u64::MAX,
            "invalid FRI reduction arity",
        ),
        (
            512,
            4096,
            vec![4],
            9,
            u64::MAX,
            "FRI cap exceeds leaf count",
        ),
        (
            512,
            4096,
            vec![4],
            4,
            4096,
            "FRI buffers exceed storage-binding limit",
        ),
        (
            512,
            4096,
            vec![0],
            0,
            65536,
            "FRI buffers exceed storage-binding limit",
        ),
    ] {
        assert_eq!(
            FriLayout::new(degree, rows, &bits, cap, limit)
                .err()
                .unwrap()
                .to_string(),
            expected
        );
    }
    Ok(())
}
