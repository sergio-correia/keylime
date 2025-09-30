import unittest
from pathlib import Path

from keylime import signing

# Useful constants for the test
PACKAGE_ROOT = Path(__file__).parents[1]
TEST_FILES = f"{PACKAGE_ROOT}/test-data/files"


class TestSigning(unittest.TestCase):
    def test_sign_gpg(self):
        try:
            signing.verify_signature_from_file(
                f"{TEST_FILES}/allowlist-pgp-key.pgp",
                f"{TEST_FILES}/allowlist.json",
                f"{TEST_FILES}/allowlist-pgp-sig.sig",
                "Testing Allowlist",
            )
        except Exception as e:
            self.fail(f"Signing raised exception: {e}!")

    def test_sign_ec(self):
        try:
            signing.verify_signature_from_file(
                f"{TEST_FILES}/allowlist-ec-key.pem",
                f"{TEST_FILES}/allowlist.json",
                f"{TEST_FILES}/allowlist-ec-sig.bin",
                "Testing Allowlist",
            )
        except Exception as e:
            self.fail(f"Signing raised exception: {e}!")

    def test_sign_bad_sig(self):
        try:
            signing.verify_signature_from_file(
                f"{TEST_FILES}/allowlist-pgp-key.pgp",
                f"{TEST_FILES}/allowlist.json",
                f"{TEST_FILES}/allowlist-invalid-sig.sig",
                "Testing Allowlist",
            )
            self.fail("Signing passed with invalid signature!")
        except Exception:
            pass

    @unittest.skipUnless(signing.HAS_PYSEQUOIA, "pysequoia not available")
    def test_pgp_signature_pysequoia(self):
        """Test PGP signature verification using pysequoia implementation."""
        with open(f"{TEST_FILES}/allowlist-pgp-key.pgp", "rb") as f:
            key = f.read()
        with open(f"{TEST_FILES}/allowlist-pgp-sig.sig", "rb") as f:
            sig = f.read()
        with open(f"{TEST_FILES}/allowlist.json", "rb") as f:
            body = f.read()

        # Valid signature should verify
        self.assertTrue(signing._verify_pgp_signature_pysequoia(key, sig, body))

        # Tampered data should fail
        tampered_body = body + b"tampered"
        with self.assertRaises(Exception):
            signing._verify_pgp_signature_pysequoia(key, sig, tampered_body)

    @unittest.skipUnless(signing.HAS_GPG, "gpg not available")
    def test_pgp_signature_gpg(self):
        """Test PGP signature verification using gpg implementation."""
        with open(f"{TEST_FILES}/allowlist-pgp-key.pgp", "rb") as f:
            key = f.read()
        with open(f"{TEST_FILES}/allowlist-pgp-sig.sig", "rb") as f:
            sig = f.read()
        with open(f"{TEST_FILES}/allowlist.json", "rb") as f:
            body = f.read()

        # Valid signature should verify
        self.assertTrue(signing._verify_pgp_signature_gpg(key, sig, body))

        # Tampered data should fail
        tampered_body = body + b"tampered"
        self.assertFalse(signing._verify_pgp_signature_gpg(key, sig, tampered_body))
