"""
This module provides a utility function to convert an APN string to a hostname.
"""


def get_hostname(apn):
    """Convert APN to hostname by extracting and reversing the hex part."""
    if ":" in apn and len(apn.split(":")[1]) >= 6:
        prefix = apn.split(":")[0]
        hex_part = apn.split(":")[1]
        # Extract the first 6 characters as pairs, then reverse them
        reversed_hex = "".join([hex_part[i : i + 2] for i in range(0, 6, 2)][::-1])
        return f"{prefix}{reversed_hex}"
    return None
