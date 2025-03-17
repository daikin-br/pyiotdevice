import logging
import unittest
from unittest.mock import patch

from pyiotdevice import calu_crc, decrypt_aes, encrypt_aes
from pyiotdevice.crypto_utils import parse_device_data
from pyiotdevice.custom_exceptions import InvalidDataException


class TestCryptoUtils(unittest.TestCase):
    def test_encrypt_decrypt_aes(self):
        key = b"1234567890123456"
        iv = b"abcdef1234567890"
        plaintext = b"This is a test message for AES encryption"

        # Encrypt the plaintext
        encrypted = encrypt_aes(key, iv, plaintext)
        self.assertNotEqual(
            plaintext, encrypted, "Encryption should alter the plaintext."
        )

        # Decrypt the ciphertext and verify it matches the original plaintext
        decrypted = decrypt_aes(key, iv, encrypted)
        self.assertEqual(
            plaintext, decrypted, "Decrypted text should match the original plaintext."
        )

    def test_calu_crc_consistency(self):
        initial = 0
        data = b"Hello CRC"
        length = len(data)
        crc1 = calu_crc(initial, data, length)
        crc2 = calu_crc(initial, data, length)
        self.assertEqual(
            crc1, crc2, "CRC calculation should be consistent for the same input."
        )

    def test_calu_crc_empty_data(self):
        initial = 0
        crc_empty = calu_crc(initial, b"", 0)
        self.assertIsInstance(crc_empty, int, "CRC of empty data should be an integer.")

    def test_parse_device_data_success(self):
        """
        Test that parse_device_data returns valid JSON.
        """
        with patch(
            "pyiotdevice.crypto_utils.decrypt_aes", return_value=b'{"status": "ok"}'
        ):
            result = parse_device_data(b"dummy_key", b"dummy_iv", b"dummy_encrypted")
            self.assertEqual(result, {"status": "ok"})

    def test_parse_device_data_invalid_json(self):
        """
        Test that parse_device_data raises InvalidDataException.
        """
        with patch("pyiotdevice.crypto_utils.decrypt_aes", return_value=b"not a json"):
            with self.assertRaises(InvalidDataException):
                parse_device_data(b"dummy_key", b"dummy_iv", b"dummy_encrypted")


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
