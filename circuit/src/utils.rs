use crate::circuit::F;
use plonky2::field::types::{Field, PrimeField64};

pub fn u128_to_felts(num: u128) -> Vec<F> {
    let mut amount_felts: Vec<F> = Vec::with_capacity(2);
    let amount_high = F::from_noncanonical_u64((num >> 64) as u64);
    let amount_low = F::from_noncanonical_u64(num as u64);
    amount_felts.push(amount_high);
    amount_felts.push(amount_low);
    amount_felts
}

pub fn felts_to_u128(felts: Vec<F>) -> u128 {
    let amount_high: u128 = felts[0].0 as u128;
    let amount_low: u128 = felts[1].0 as u128;
    (amount_high << 64) | amount_low
}

// Encodes an 8-byte string into a single field element
pub fn string_to_felt(input: &str) -> F {
    // Convert string to UTF-8 bytes
    let bytes = input.as_bytes();

    let mut arr = [0u8; 8];
    arr[..bytes.len()].copy_from_slice(bytes);

    let num = u64::from_le_bytes(arr);
    F::from_noncanonical_u64(num)
}

/// Converts a given slice into its field element representation.
pub fn bytes_to_felts(input: &[u8]) -> Vec<F> {
    const BYTES_PER_ELEMENT: usize = 8;

    let mut field_elements: Vec<F> = Vec::new();
    for chunk in input.chunks(BYTES_PER_ELEMENT) {
        let mut bytes = [0u8; 8];
        bytes[..chunk.len()].copy_from_slice(chunk);
        // Convert the chunk to a field element.
        let value = u64::from_le_bytes(bytes);
        let field_element = F::from_noncanonical_u64(value);
        field_elements.push(field_element);
    }

    field_elements
}

/// Converts a given field element slice into its byte representation.
pub fn felts_to_bytes(input: &[F]) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();

    for field_element in input {
        let value = field_element.to_noncanonical_u64();
        let value_bytes = value.to_le_bytes();
        bytes.extend_from_slice(&value_bytes);
    }

    bytes
}

pub type Digest = [F; 4];

pub const BYTES_PER_FELT: usize = 8;
pub const HASH_NUM_FELTS: usize = 4;

/// Converts a fixed-size byte array into an array of field elements.
pub fn array_to_field_elements<const NUM_FELTS: usize>(input: &[u8]) -> [F; NUM_FELTS] {
    assert_eq!(
        input.len(),
        NUM_FELTS * BYTES_PER_FELT,
        "Invalid input length"
    );

    let mut result = [F::ZERO; NUM_FELTS];
    for (i, out) in result.iter_mut().enumerate().take(NUM_FELTS) {
        let offset = i * BYTES_PER_FELT;
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&input[offset..offset + BYTES_PER_FELT]);
        let value = u64::from_le_bytes(bytes);
        *out = F::from_noncanonical_u64(value);
    }

    result
}

#[cfg(test)]
mod tests {
    use plonky2::field::types::Field64;

    use super::*;

    // Helper to create F from a u64 for concise test cases
    fn f(val: u64) -> F {
        F::from_noncanonical_u64(val)
    }

    #[test]
    fn test_u128_to_felts_to_u128_round_trip() {
        // Test cases: zero, small, large, max u128, and random values
        let test_cases = [
            0u128,
            1u128,
            0x1234567890abcdefu128,
            u128::MAX,
            (1u128 << 64) - 1,            // Max value for high part
            (1u128 << 64) | 0xabcdefu128, // Mixed high and low
        ];

        for num in test_cases {
            // u128 -> Vec<F>
            let felts = u128_to_felts(num);
            assert_eq!(felts.len(), 2, "Expected exactly two field elements");

            // Vec<F> -> u128
            let round_trip_num = felts_to_u128(felts.clone());

            // Check that the high and low parts match
            let expected_high = (num >> 64) as u64;
            let expected_low = num as u64;
            let expected = ((expected_high as u128) << 64) | (expected_low as u128);
            assert_eq!(
                round_trip_num, expected,
                "Round trip failed for input {}. Expected {}, got {}",
                num, expected, round_trip_num
            );
        }
    }

    #[test]
    fn test_felts_to_u128_to_felts_round_trip() {
        // Test cases: various field element pairs within the field order
        let test_cases = [
            (f(0), f(0)),
            (f(1), f(1)),
            (f(0x1234567890abcdef), f(0xabcdef1234567890)),
            (f(F::ORDER - 1), f(F::ORDER - 1)), // Max field element
            (f(0), f(F::ORDER - 1)),            // Zero high, max low
            (f(F::ORDER - 1), f(0)),            // Max high, zero low
        ];

        for (high, low) in test_cases {
            let felts = vec![high, low];

            // Vec<F> -> u128
            let num = felts_to_u128(felts.clone());

            // u128 -> Vec<F>
            let round_trip_felts = u128_to_felts(num);
            assert_eq!(
                round_trip_felts, felts,
                "Round trip failed for input {:?}. Got {:?}",
                felts, round_trip_felts
            );
        }
    }

    #[test]
    fn test_edge_cases() {
        // Test specific edge cases
        let num = u128::MAX;
        let felts = u128_to_felts(num);
        assert_eq!(felts.len(), 2);
        let result = felts_to_u128(felts);
        let expected_high = (u128::MAX >> 64) as u64;
        let expected_low = u128::MAX as u64;
        let expected = ((expected_high as u128) << 64) | (expected_low as u128);
        assert_eq!(result, expected);

        // Test zero
        let num = 0u128;
        let felts = u128_to_felts(num);
        assert_eq!(felts, vec![f(0), f(0)]);
        let result = felts_to_u128(felts);
        assert_eq!(result, 0);
    }
}
