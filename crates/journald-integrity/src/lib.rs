//! Anti-forensic detection for systemd journal files.
//!
//! Detects sequence gaps, timestamp regressions, truncation, and suspicious state.

/// A detected integrity anomaly in a journal file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IntegrityIndicator {
    pub kind: IntegrityKind,
    pub description: String,
    pub seqnum_start: Option<u64>,
    pub seqnum_end: Option<u64>,
}

/// Category of integrity anomaly.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum IntegrityKind {
    /// Entries deleted between two sequence numbers.
    SequenceGap,
    /// Realtime timestamp decreases (should be monotonically non-decreasing).
    TimestampRegression,
    /// File ends before `tail_object_offset` + last object size.
    Truncation,
    /// Header `state` field is ONLINE (unclean shutdown or active write).
    InvalidState,
}

/// Detect sequence number gaps in a sorted list of sequence numbers.
///
/// A gap at `[A, B]` where `B > A + 1` means `B - A - 1` entries were deleted.
pub fn detect_sequence_gaps(seqnums: &[u64]) -> Vec<IntegrityIndicator> {
    todo!()
}

/// Detect timestamp regressions in a list of realtime timestamps (microseconds).
///
/// A regression is any timestamp strictly less than the previous one.
pub fn detect_timestamp_regressions(timestamps_us: &[u64]) -> Vec<IntegrityIndicator> {
    todo!()
}

/// Detect file truncation.
///
/// Returns `Some(indicator)` if `file_size < tail_object_offset + last_object_size`.
pub fn detect_truncation(
    file_size: u64,
    tail_object_offset: u64,
    last_object_size: u64,
) -> Option<IntegrityIndicator> {
    todo!()
}

/// Detect suspicious journal state.
///
/// State byte `1` means ONLINE (file was not cleanly closed). This is suspicious
/// when the file is being analysed forensically (it could mean active tampering
/// or that the machine crashed, hiding deleted entries).
pub fn detect_online_state(state_byte: u8) -> Option<IntegrityIndicator> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_gaps_in_consecutive_seqnums_returns_empty() {
        let seqnums = vec![1u64, 2, 3, 4, 5];
        let indicators = detect_sequence_gaps(&seqnums);
        assert!(indicators.is_empty());
    }

    #[test]
    fn single_gap_detected() {
        // [1, 2, 5] → gap at 3-4
        let seqnums = vec![1u64, 2, 5];
        let indicators = detect_sequence_gaps(&seqnums);
        assert_eq!(indicators.len(), 1);
        assert_eq!(indicators[0].kind, IntegrityKind::SequenceGap);
        assert_eq!(indicators[0].seqnum_start, Some(2));
        assert_eq!(indicators[0].seqnum_end, Some(5));
    }

    #[test]
    fn multiple_gaps_detected() {
        // [1, 3, 7] → two gaps
        let seqnums = vec![1u64, 3, 7];
        let indicators = detect_sequence_gaps(&seqnums);
        assert_eq!(indicators.len(), 2);
        assert!(indicators.iter().all(|i| i.kind == IntegrityKind::SequenceGap));
    }

    #[test]
    fn gap_count_is_correct() {
        // gap from 2 to 5 = 2 deleted entries (3 and 4)
        let seqnums = vec![2u64, 5];
        let indicators = detect_sequence_gaps(&seqnums);
        assert_eq!(indicators.len(), 1);
        assert_eq!(indicators[0].seqnum_start, Some(2));
        assert_eq!(indicators[0].seqnum_end, Some(5));
        // description should mention the count
        assert!(indicators[0].description.contains('2') || indicators[0].description.contains("deleted"));
    }

    #[test]
    fn no_regressions_in_sorted_timestamps_returns_empty() {
        let ts = vec![100u64, 200, 300, 400];
        let indicators = detect_timestamp_regressions(&ts);
        assert!(indicators.is_empty());
    }

    #[test]
    fn timestamp_regression_detected() {
        // [100, 200, 150] → regression at index 2
        let ts = vec![100u64, 200, 150];
        let indicators = detect_timestamp_regressions(&ts);
        assert_eq!(indicators.len(), 1);
        assert_eq!(indicators[0].kind, IntegrityKind::TimestampRegression);
    }

    #[test]
    fn truncation_detected_when_file_smaller_than_expected() {
        // tail_object at offset 1000, last object size 256 → need at least 1256 bytes
        let ind = detect_truncation(500, 1000, 256);
        assert!(ind.is_some());
        assert_eq!(ind.unwrap().kind, IntegrityKind::Truncation);
    }

    #[test]
    fn no_truncation_when_file_size_sufficient() {
        let ind = detect_truncation(2000, 1000, 256);
        assert!(ind.is_none());
    }

    #[test]
    fn online_state_is_suspicious() {
        let ind = detect_online_state(1);
        assert!(ind.is_some());
        assert_eq!(ind.unwrap().kind, IntegrityKind::InvalidState);
    }

    #[test]
    fn offline_state_is_clean() {
        let ind = detect_online_state(0);
        assert!(ind.is_none());
    }

    #[test]
    fn archived_state_is_clean() {
        let ind = detect_online_state(2);
        assert!(ind.is_none());
    }
}
