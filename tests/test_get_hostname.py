import unittest

from pyiotdevice import get_hostname


class TestGetHostname(unittest.TestCase):
    def test_valid_apn(self):
        # For an APN in the format "prefix:hex" where hex is at least 6 characters,
        # the function should extract the prefix and reverse the first 6 hex characters.
        apn = "abc:112233"
        # Splitting "112233" into two-character groups: "11", "22", "33"
        # Reversed order gives: "33", "22", "11", then appended to the prefix "abc"
        expected = "abc332211"
        self.assertEqual(get_hostname(apn), expected)

    def test_no_colon(self):
        # If there's no colon in the string, get_hostname should return None.
        apn = "abc112233"
        self.assertIsNone(get_hostname(apn))

    def test_insufficient_hex_length(self):
        # If the part after the colon is less than 6 characters, it should return None.
        apn = "abc:1234"
        self.assertIsNone(get_hostname(apn))

    def test_valid_apn_with_extra_data(self):
        # Even if there are extra characters after the first 6 hex characters,
        # the function only considers the first 6.
        apn = "host:abcdef1234"
        # "abcdef" split into groups: "ab", "cd", "ef" and reversed becomes "efcdab".
        expected = "hostefcdab"
        self.assertEqual(get_hostname(apn), expected)


if __name__ == "__main__":
    unittest.main()
