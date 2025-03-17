"""
This module provides functions to retrieve device information via HTTP requests.
It includes both synchronous and asynchronous methods to:
  - Send HTTP requests,
  - Process and decode Base64 responses,
  - Validate responses using CRC checks,
  - Decrypt the response data, and
  - Parse the decrypted data as JSON.

Exceptions are raised for invalid data, checksum errors, and JSON decoding issues.
"""

import base64
import logging

from .crypto_utils import calu_crc, parse_device_data
from .custom_exceptions import InvalidDataException
from .socket_utils import DEFAULT_PORT, async_send_http_request, send_http_request

# Enable logging
_LOGGER = logging.getLogger(__name__)


def check_not_found_case(response):
    """Check if the response indicates a 'not found' case."""
    return "404 Not Found" not in response


def get_thing_info(ip_address, key, api_endpoint):  # pylint: disable=too-many-locals
    """Get device related information."""
    try:
        # Prepare the raw HTTP GET request
        request_str = f"GET /{api_endpoint} HTTP/1.1\r\nhost: {ip_address}\r\n\r\n"

        # Use the common function to send the request and get the parsed response
        headers, body = send_http_request(ip_address, DEFAULT_PORT, request_str)

        # Process the response body
        _LOGGER.debug("Thing status received. Header: %s, body: %s", headers, body)

        # Extract the Base64 encoded body
        base64_body = body

        # Decode the Base64 data
        received_data = base64.b64decode(base64_body)

        if len(received_data) == 0:
            _LOGGER.debug("Received empty data.")
            raise InvalidDataException()

        # Validate the checksum
        total_len = len(received_data)
        checksum = calu_crc(0, received_data, total_len - 2) & 0xFFFF
        checksum_pkt = ((received_data[total_len - 1] & 0xFF) << 8) | (
            received_data[total_len - 2] & 0xFF
        )
        _LOGGER.debug(
            "Calculated checksum: %s, Packet checksum: %s", checksum, checksum_pkt
        )

        if checksum != checksum_pkt:
            _LOGGER.debug("Checksum validation failed.")
            raise InvalidDataException()

        # Extract AES IV and encrypted data
        aes_iv = received_data[:16]
        encrypted_data = received_data[17:-2]

        # Extract AES Key
        aes_key = base64.b64decode(key)

        device_status = parse_device_data(aes_key, aes_iv, encrypted_data)
        return device_status

    except Exception as e:  # pylint: disable=broad-exception-caught
        _LOGGER.debug("Unable to fetch device data: %s", e)
        return False


async def async_get_thing_info(
    ip_address, key, api_endpoint
):  # pylint: disable=too-many-locals
    """Asynchronously get device-related information using a raw socket."""
    try:
        # Prepare the raw HTTP GET request string
        request_str = f"GET /{api_endpoint} HTTP/1.1\r\nhost: {ip_address}\r\n\r\n"

        # Call the async socket-based HTTP request function and unpack headers and body.
        headers, body = await async_send_http_request(
            ip_address, DEFAULT_PORT, request_str
        )

        _LOGGER.debug("Thing status received. Header: %s, body: %s", headers, body)

        # Process the response body (expected to be Base64 encoded)
        base64_body = body
        received_data = base64.b64decode(base64_body)
        if len(received_data) == 0:
            _LOGGER.debug("Received empty data.")
            raise InvalidDataException()

        # Validate the checksum
        total_len = len(received_data)
        checksum = calu_crc(0, received_data, total_len - 2) & 0xFFFF
        checksum_pkt = ((received_data[total_len - 1] & 0xFF) << 8) | (
            received_data[total_len - 2] & 0xFF
        )
        _LOGGER.debug(
            "Calculated checksum: %s, Packet checksum: %s", checksum, checksum_pkt
        )

        if checksum != checksum_pkt:
            _LOGGER.debug("Checksum validation failed.")
            raise InvalidDataException()

        # Extract AES IV and encrypted data
        aes_iv = received_data[:16]
        encrypted_data = received_data[17:-2]

        # Decode the AES Key and decrypt the data
        aes_key = base64.b64decode(key)

        device_status = parse_device_data(aes_key, aes_iv, encrypted_data)
        return device_status

    except Exception as e:  # pylint: disable=broad-exception-caught
        _LOGGER.debug("Unable to fetch device data: %s", e)
        return False
