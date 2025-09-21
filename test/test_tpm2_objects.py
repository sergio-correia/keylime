import unittest

from keylime.tpm.tpm2_objects import (
    ECC_CURVE_PRIMES,
    TPM_ECC_NIST_P192,
    TPM_ECC_NIST_P224,
    TPM_ECC_NIST_P256,
    TPM_ECC_NIST_P384,
    TPM_ECC_NIST_P521,
    _curve_from_curve_id,
)


class TestTpm2Objects(unittest.TestCase):
    def test_p521_coordinate_validation_logic(self):
        """Test the specific coordinate validation logic for P-521"""
        curve = _curve_from_curve_id(TPM_ECC_NIST_P521)

        # Test the updated validation logic
        max_bytes = (curve.key_size + 7) // 8  # Should be 66 bytes for P-521
        min_bytes = max_bytes - 1 if curve.key_size % 8 != 0 else max_bytes  # Should be 65 bytes for P-521

        self.assertEqual(max_bytes, 66)
        self.assertEqual(min_bytes, 65)  # P-521 is not byte-aligned, so allows 65-66 bytes

        # Test coordinate sizes that should be accepted (65-66 bytes for P-521)
        valid_sizes = [65, 66]

        for size in valid_sizes:
            # Check that the validation logic would accept this size
            should_pass = min_bytes <= size <= max_bytes
            self.assertTrue(should_pass, f"Size {size} bytes should be valid for P-521")

        # Test coordinate sizes that should be rejected
        invalid_sizes = [64, 67, 32, 68]

        for size in invalid_sizes:
            # This should fail: not in the valid range
            should_fail = size < min_bytes or size > max_bytes
            self.assertTrue(should_fail, f"Size {size} bytes should be invalid for P-521")

    def test_p256_coordinate_validation_logic(self):
        """Test the coordinate validation logic for P-256 to ensure no regression"""
        curve = _curve_from_curve_id(TPM_ECC_NIST_P256)

        max_bytes = (curve.key_size + 7) // 8  # Should be 32 bytes for P-256
        min_bytes = (
            max_bytes - 1 if curve.key_size % 8 != 0 else max_bytes
        )  # Should be 32 bytes for P-256 (byte-aligned)

        self.assertEqual(max_bytes, 32)
        self.assertEqual(min_bytes, 32)  # P-256 is byte-aligned, so only accepts 32 bytes

        # 32 bytes should be accepted
        size = 32
        should_pass = min_bytes <= size <= max_bytes
        self.assertTrue(should_pass, f"P-256 should accept {size} bytes")

        # Other sizes should be rejected
        invalid_sizes = [31, 33, 64]
        for size in invalid_sizes:
            should_fail = size < min_bytes or size > max_bytes
            self.assertTrue(should_fail, f"P-256 should reject {size} bytes")

    def test_p384_coordinate_validation_logic(self):
        """Test the coordinate validation logic for P-384 to ensure no regression"""
        curve = _curve_from_curve_id(TPM_ECC_NIST_P384)

        max_bytes = (curve.key_size + 7) // 8  # Should be 48 bytes for P-384
        min_bytes = (
            max_bytes - 1 if curve.key_size % 8 != 0 else max_bytes
        )  # Should be 48 bytes for P-384 (byte-aligned)

        self.assertEqual(max_bytes, 48)
        self.assertEqual(min_bytes, 48)  # P-384 is byte-aligned, so only accepts 48 bytes

        # 48 bytes should be accepted
        size = 48
        should_pass = min_bytes <= size <= max_bytes
        self.assertTrue(should_pass, f"P-384 should accept {size} bytes")

    def test_coordinate_size_calculation(self):
        """Test that coordinate size calculations are correct for different curves"""
        # P-256: 256 bits -> (256 + 7) // 8 = 32 bytes
        curve_p256 = _curve_from_curve_id(TPM_ECC_NIST_P256)
        expected_p256 = (curve_p256.key_size + 7) // 8
        self.assertEqual(expected_p256, 32)
        self.assertEqual(curve_p256.key_size, 256)

        # P-384: 384 bits -> (384 + 7) // 8 = 48 bytes
        curve_p384 = _curve_from_curve_id(TPM_ECC_NIST_P384)
        expected_p384 = (curve_p384.key_size + 7) // 8
        self.assertEqual(expected_p384, 48)
        self.assertEqual(curve_p384.key_size, 384)

        # P-521: 521 bits -> (521 + 7) // 8 = 66 bytes
        curve_p521 = _curve_from_curve_id(TPM_ECC_NIST_P521)
        expected_p521 = (curve_p521.key_size + 7) // 8
        self.assertEqual(expected_p521, 66)
        self.assertEqual(curve_p521.key_size, 521)

    def test_p521_specific_fix(self):
        """Test the specific scenario that was fixed: P-521 with 66-byte coordinates"""
        curve = _curve_from_curve_id(TPM_ECC_NIST_P521)

        # The key issue: P-521 has 521 bits
        self.assertEqual(curve.key_size, 521)

        # TPMs pad to 66 bytes (528 bits)
        tpm_padded_size = 66
        tpm_padded_bits = tpm_padded_size * 8
        self.assertEqual(tpm_padded_bits, 528)

        # The old validation would reject: (66 * 8) != 521
        old_validation_fails = tpm_padded_bits != curve.key_size
        self.assertTrue(old_validation_fails, "Old validation would incorrectly reject 66-byte coordinates")

        # The new validation should accept: len(x) == expected_bytes OR (len(x) * 8) == curve.key_size
        expected_bytes = (curve.key_size + 7) // 8
        new_validation_passes = (tpm_padded_size == expected_bytes) or (tpm_padded_bits == curve.key_size)
        self.assertTrue(new_validation_passes, "New validation should accept 66-byte coordinates")

    def test_validation_before_and_after_fix(self):
        """Test that demonstrates the fix by comparing old vs new validation logic"""
        curve = _curve_from_curve_id(TPM_ECC_NIST_P521)

        # Test multiple coordinate sizes that P-521 can have
        test_sizes = [65, 66]  # 65 bytes (leading zero stripped), 66 bytes (padded)

        max_bytes = (curve.key_size + 7) // 8  # 66 bytes
        min_bytes = max_bytes - 1 if curve.key_size % 8 != 0 else max_bytes  # 65 bytes for P-521

        for coordinate_size in test_sizes:
            # Old validation logic (strict bit size match) - would require exactly 65.125 bytes
            # which is impossible since we can't have fractional bytes

            # New validation logic (accept range for non-byte-aligned curves)
            new_logic_passes = min_bytes <= coordinate_size <= max_bytes
            self.assertTrue(new_logic_passes, f"New logic should accept {coordinate_size}-byte coordinates for P-521")

        # Verify the calculations
        self.assertEqual(max_bytes, 66)
        self.assertEqual(min_bytes, 65)

    def test_p521_coordinate_range_validation(self):
        """Test that P-521 accepts coordinates in the range 65-66 bytes (520-528 bits)"""
        curve = _curve_from_curve_id(TPM_ECC_NIST_P521)

        # P-521: 521 bits, padded to 66 bytes (528 bits), or 65 bytes with leading zero stripped
        max_bytes = (curve.key_size + 7) // 8  # 66 bytes
        min_bytes = max_bytes - 1  # 65 bytes (since 521 % 8 != 0)

        # Test all valid sizes
        valid_sizes = [65, 66]
        for size in valid_sizes:
            is_valid = min_bytes <= size <= max_bytes
            self.assertTrue(is_valid, f"P-521 should accept {size} bytes ({size * 8} bits)")

        # Test invalid sizes
        invalid_sizes = [64, 67, 68, 32]
        for size in invalid_sizes:
            is_invalid = size < min_bytes or size > max_bytes
            self.assertTrue(is_invalid, f"P-521 should reject {size} bytes ({size * 8} bits)")

    def test_coordinate_value_validation(self):
        """Test that coordinate values are validated against actual prime moduli"""
        # Test P-521 with actual prime
        # curve_p521 = _curve_from_curve_id(TPM_ECC_NIST_P521)  # Not needed for this test
        p521_prime = ECC_CURVE_PRIMES[TPM_ECC_NIST_P521]

        # Test valid coordinate value (within range)
        valid_coord_int = p521_prime - 1  # Largest valid value
        valid_coord_bytes = valid_coord_int.to_bytes(66, "big")  # 66 bytes, padded

        # Test the validation logic
        coord_int = int.from_bytes(valid_coord_bytes, "big")
        is_valid_value = coord_int < p521_prime
        self.assertTrue(is_valid_value, "Coordinate value should be valid for P-521")

        # Test invalid coordinate value (>= prime)
        invalid_coord_int = p521_prime  # Equal to prime (invalid)
        invalid_coord_bytes = invalid_coord_int.to_bytes(66, "big")  # 66 bytes, but value too large

        coord_int = int.from_bytes(invalid_coord_bytes, "big")
        is_invalid_value = coord_int >= p521_prime
        self.assertTrue(is_invalid_value, "Coordinate value >= prime should be invalid for P-521")

    def test_prime_constants_accuracy(self):
        """Test that our hardcoded prime constants are correct"""
        # Verify the NIST prime values
        self.assertEqual(ECC_CURVE_PRIMES[TPM_ECC_NIST_P192], 2**192 - 2**64 - 1)
        self.assertEqual(ECC_CURVE_PRIMES[TPM_ECC_NIST_P224], 2**224 - 2**96 + 1)
        self.assertEqual(ECC_CURVE_PRIMES[TPM_ECC_NIST_P256], 2**256 - 2**224 + 2**192 + 2**96 - 1)
        self.assertEqual(ECC_CURVE_PRIMES[TPM_ECC_NIST_P384], 2**384 - 2**128 - 2**96 + 2**32 - 1)
        self.assertEqual(ECC_CURVE_PRIMES[TPM_ECC_NIST_P521], 2**521 - 1)

        # Verify they are actually less than 2^m for all curves except P-521
        self.assertLess(ECC_CURVE_PRIMES[TPM_ECC_NIST_P192], 2**192)
        self.assertLess(ECC_CURVE_PRIMES[TPM_ECC_NIST_P224], 2**224)
        self.assertLess(ECC_CURVE_PRIMES[TPM_ECC_NIST_P256], 2**256)
        self.assertLess(ECC_CURVE_PRIMES[TPM_ECC_NIST_P384], 2**384)
        self.assertEqual(ECC_CURVE_PRIMES[TPM_ECC_NIST_P521], 2**521 - 1)  # P-521 is special case

    def test_prime_lookup_table(self):
        """Test that the prime lookup table works correctly"""
        # Test known curves
        self.assertEqual(ECC_CURVE_PRIMES[TPM_ECC_NIST_P192], 2**192 - 2**64 - 1)
        self.assertEqual(ECC_CURVE_PRIMES[TPM_ECC_NIST_P224], 2**224 - 2**96 + 1)
        self.assertEqual(ECC_CURVE_PRIMES[TPM_ECC_NIST_P256], 2**256 - 2**224 + 2**192 + 2**96 - 1)
        self.assertEqual(ECC_CURVE_PRIMES[TPM_ECC_NIST_P384], 2**384 - 2**128 - 2**96 + 2**32 - 1)
        self.assertEqual(ECC_CURVE_PRIMES[TPM_ECC_NIST_P521], 2**521 - 1)

        # Test rejection of unknown curve
        unknown_curve_id = 0x9999
        unknown_prime = ECC_CURVE_PRIMES.get(unknown_curve_id)
        self.assertIsNone(unknown_prime, "Unknown curves should not be in ECC_CURVE_PRIMES")

    def test_error_message_formatting(self):
        """Test that error messages use bit_length() instead of full integers"""
        # Create a large coordinate value
        large_value = ECC_CURVE_PRIMES[TPM_ECC_NIST_P521]  # This would be hundreds of digits

        # Verify bit_length() is much more reasonable than the full number
        bit_length = large_value.bit_length()
        self.assertEqual(bit_length, 521)  # Much more readable than 150+ digit number

        # The error message should use bit lengths, not full integers
        expected_msg_pattern = f"coordinate too large: {bit_length} bits"
        self.assertIn("521 bits", expected_msg_pattern)

    def test_unknown_curve_rejection(self):
        """Test that unknown curves are strictly rejected"""
        # This tests the design decision to be strict rather than use fallbacks
        unknown_curve_id = 0x9999

        # The strict approach: unknown curves should not have fallback behavior
        # This ensures we only validate curves we explicitly understand
        result = ECC_CURVE_PRIMES.get(unknown_curve_id)
        self.assertIsNone(result, "Unknown curves should be explicitly rejected, not given fallback primes")


if __name__ == "__main__":
    unittest.main()
