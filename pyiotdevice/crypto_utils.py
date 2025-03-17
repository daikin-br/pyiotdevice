"""
This module provides cryptographic utilities for the pyiotdevice library.
It includes functions for:
  - Calculating CRC checksums,
  - Encrypting data using AES in CFB mode, and
  - Decrypting data using AES in CFB mode.
"""

import json
import logging

from Crypto.Cipher import AES

from .custom_exceptions import InvalidDataException

_LOGGER = logging.getLogger(__name__)

# CRC Table
CRC_TB = [
    0,
    4129,
    8258,
    12387,
    16516,
    20645,
    24774,
    28903,
    33032,
    37161,
    41290,
    45419,
    49548,
    53677,
    57806,
    61935,
    4657,
    528,
    12915,
    8786,
    21173,
    17044,
    29431,
    25302,
    37689,
    33560,
    45947,
    41818,
    54205,
    50076,
    62463,
    58334,
    9314,
    13379,
    1056,
    5121,
    25830,
    29895,
    17572,
    21637,
    42346,
    46411,
    34088,
    38153,
    58862,
    62927,
    50604,
    54669,
    13907,
    9842,
    5649,
    1584,
    30423,
    26358,
    22165,
    18100,
    46939,
    42874,
    38681,
    34616,
    63455,
    59390,
    55197,
    51132,
    18628,
    22757,
    26758,
    30887,
    2112,
    6241,
    10242,
    14371,
    51660,
    55789,
    59790,
    63919,
    35144,
    39273,
    43274,
    47403,
    23285,
    19156,
    31415,
    27286,
    6769,
    2640,
    14899,
    10770,
    56317,
    52188,
    64447,
    60318,
    39801,
    35672,
    47931,
    43802,
    27814,
    31879,
    19684,
    23749,
    11298,
    15363,
    3168,
    7233,
    60846,
    64911,
    52716,
    56781,
    44330,
    48395,
    36200,
    40265,
    32407,
    28342,
    24277,
    20212,
    15891,
    11826,
    7761,
    3696,
    65439,
    61374,
    57309,
    53244,
    48923,
    44858,
    40793,
    36728,
    37256,
    33193,
    45514,
    41451,
    53516,
    49453,
    61774,
    57711,
    4224,
    161,
    12482,
    8419,
    20484,
    16421,
    28742,
    24679,
    33721,
    37784,
    41979,
    46042,
    49981,
    54044,
    58239,
    62302,
    689,
    4752,
    8947,
    13010,
    16949,
    21012,
    25207,
    29270,
    46570,
    42443,
    38312,
    34185,
    62830,
    58703,
    54572,
    50445,
    13538,
    9411,
    5280,
    1153,
    29798,
    25671,
    21540,
    17413,
    42971,
    47098,
    34713,
    38840,
    59231,
    63358,
    50973,
    55100,
    9939,
    14066,
    1681,
    5808,
    26199,
    30326,
    17941,
    22068,
    55628,
    51565,
    63758,
    59695,
    39368,
    35305,
    47498,
    43435,
    22596,
    18533,
    30726,
    26663,
    6336,
    2273,
    14466,
    10403,
    52093,
    56156,
    60223,
    64286,
    35833,
    39896,
    43963,
    48026,
    19061,
    23124,
    27191,
    31254,
    2801,
    6864,
    10931,
    14994,
    64814,
    60687,
    56684,
    52557,
    48554,
    44427,
    40424,
    36297,
    31782,
    27655,
    23652,
    19525,
    15522,
    11395,
    7392,
    3265,
    61215,
    65342,
    53085,
    57212,
    44955,
    49082,
    36825,
    40952,
    28183,
    32310,
    20053,
    24180,
    11923,
    16050,
    3793,
    7920,
]


# CRC Calculation Function
def calu_crc(initial, data, length):
    """
    Calculate CRC checksum based on the provided Java logic.
    """
    _LOGGER.debug("Starting CRC calculation...")
    crc = initial & 0xFFFF ^ 0xFFFFFFFF
    for i in range(length):
        crc = CRC_TB[((crc & 0xFFFF) >> 8) ^ (data[i] & 0xFF)] ^ ((crc & 0xFFFF) << 8)
        crc &= 0xFFFF
    crc_result = crc ^ 0xFFFFFFFF
    _LOGGER.debug("CRC calculation complete: %s", crc_result)
    return crc_result


# AES Encryption Function
def encrypt_aes(aes_key, aes_iv, raw_data):
    """
    Encrypt data using AES in CFB mode.
    """
    cipher = AES.new(aes_key, AES.MODE_CFB, iv=aes_iv, segment_size=128)
    return cipher.encrypt(raw_data)


# AES Decryption Function
def decrypt_aes(aes_key, aes_iv, encrypted_data):
    """
    Decrypt data using AES in CFB mode.
    """
    cipher = AES.new(aes_key, AES.MODE_CFB, iv=aes_iv, segment_size=128)
    return cipher.decrypt(encrypted_data)


# Parse device data
def parse_device_data(aes_key, aes_iv, encrypted_data):
    """
    Decrypts the encrypted data using AES and parses the result as JSON.

    Args:
        aes_key (bytes): The AES key.
        aes_iv (bytes): The AES initialization vector.
        encrypted_data (bytes): The encrypted payload.

    Returns:
        dict: The parsed device status.

    Raises:
        InvalidDataException: If JSON decoding fails.
    """
    decrypted_data = decrypt_aes(aes_key, aes_iv, encrypted_data)
    decrypted_str = decrypted_data.decode("utf-8")
    try:
        return json.loads(decrypted_str)
    except json.JSONDecodeError as exc:
        _LOGGER.debug("Failed to decode decrypted data as JSON.")
        raise InvalidDataException() from exc
