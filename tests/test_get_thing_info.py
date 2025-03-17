import base64
import importlib

import pytest

import pyiotdevice.crypto_utils as cu

# Import the get_thing_info module so we can patch its internal functions.
gti = importlib.import_module("pyiotdevice.get_thing_info")


# --- Shared Dummy Data and Functions ---

expected_status = {"status": "ok"}
dummy_decrypted_data = b'{"status": "ok"}'
# Our dummy packet will have a checksum that decodes to 12345 (0x3039).
expected_checksum = 12345


def dummy_send_http_request(ip_address, port, request_str):
    """
    Dummy synchronous HTTP request function.
    Constructs a fake packet:
      - First 16 bytes: AES IV (dummy data)
      - 1 extra dummy byte
      - Dummy encrypted payload bytes
      - Last 2 bytes: Checksum (0x39, 0x30 for 12345)
    Encodes the packet in Base64.
    """
    aes_iv = b"A" * 16
    dummy_byte = b"B"
    encrypted_data = b"ENCRYPTED"
    packet_without_checksum = aes_iv + dummy_byte + encrypted_data
    # For expected_checksum 12345 (0x3039): lower byte 0x39, higher byte 0x30.
    packet = packet_without_checksum + b"\x39\x30"
    body = base64.b64encode(packet).decode("utf-8")
    return ("dummy_headers", body)


async def dummy_async_send_http_request(ip_address, port, request_str):
    """
    Dummy asynchronous HTTP request function.
    """
    aes_iv = b"A" * 16
    dummy_byte = b"B"
    encrypted_data = b"ENCRYPTED"
    packet_without_checksum = aes_iv + dummy_byte + encrypted_data
    packet = packet_without_checksum + b"\x39\x30"
    body = base64.b64encode(packet).decode("utf-8")
    return ("dummy_headers", body)


def dummy_decrypt_aes(aes_key, aes_iv, encrypted_data):
    """Simulate decryption by returning our dummy valid JSON bytes."""
    return dummy_decrypted_data


def dummy_calu_crc_valid(init, data, length):
    """Simulate a valid checksum calculation by always returning expected_checksum."""
    return expected_checksum


def dummy_calu_crc_invalid(init, data, length):
    """Simulate an invalid checksum by returning a different value."""
    return expected_checksum + 1


# --- Tests for check_not_found_case ---


def test_check_not_found_case():
    # This function simply returns True if "404 Not Found" is NOT in the response.
    assert gti.check_not_found_case("200 OK") is True
    assert gti.check_not_found_case("404 Not Found") is False


# --- Synchronous get_thing_info Tests ---


def test_get_thing_info_success(monkeypatch):
    monkeypatch.setattr(gti, "send_http_request", dummy_send_http_request)
    monkeypatch.setattr(gti, "calu_crc", dummy_calu_crc_valid)
    monkeypatch.setattr(cu, "decrypt_aes", dummy_decrypt_aes)

    dummy_key = base64.b64encode(b"1234567890123456").decode("utf-8")
    ip_address = "192.168.1.10"
    api_endpoint = "api/info"

    result = gti.get_thing_info(ip_address, dummy_key, api_endpoint)
    assert result == expected_status


def test_get_thing_info_empty_data(monkeypatch):
    # Simulate a response with empty data to cover lines 40-41.
    def dummy_send_http_request_empty(ip_address, port, request_str):
        body = base64.b64encode(b"").decode("utf-8")
        return ("dummy_headers", body)

    monkeypatch.setattr(gti, "send_http_request", dummy_send_http_request_empty)
    monkeypatch.setattr(gti, "calu_crc", dummy_calu_crc_valid)
    dummy_key = base64.b64encode(b"1234567890123456").decode("utf-8")
    ip_address = "192.168.1.10"
    api_endpoint = "api/info"
    result = gti.get_thing_info(ip_address, dummy_key, api_endpoint)
    # When received_data is empty, the function should raise InvalidDataException,
    # then catch it and return False.
    assert result is False


def test_get_thing_info_invalid_checksum(monkeypatch):
    # Simulate an invalid checksum scenario (lines 50-51).
    monkeypatch.setattr(gti, "send_http_request", dummy_send_http_request)
    monkeypatch.setattr(gti, "calu_crc", dummy_calu_crc_invalid)
    dummy_key = base64.b64encode(b"1234567890123456").decode("utf-8")
    ip_address = "192.168.1.10"
    api_endpoint = "api/info"
    result = gti.get_thing_info(ip_address, dummy_key, api_endpoint)
    assert result is False


def test_get_thing_info_json_decode_error(monkeypatch):
    # Simulate a decryption that returns invalid JSON (covering lines 82-126).
    monkeypatch.setattr(gti, "send_http_request", dummy_send_http_request)
    monkeypatch.setattr(gti, "calu_crc", dummy_calu_crc_valid)
    # Force decrypt_aes to return a non-JSON byte string.
    monkeypatch.setattr(cu, "decrypt_aes", lambda key, iv, data: b"not a json")
    dummy_key = base64.b64encode(b"1234567890123456").decode("utf-8")
    ip_address = "192.168.1.10"
    api_endpoint = "api/info"
    result = gti.get_thing_info(ip_address, dummy_key, api_endpoint)
    # The function should catch the JSONDecodeError and return False.
    assert result is False


# --- Asynchronous async_get_thing_info Tests ---


@pytest.mark.asyncio
async def test_async_get_thing_info_success(monkeypatch):
    monkeypatch.setattr(gti, "async_send_http_request", dummy_async_send_http_request)
    monkeypatch.setattr(gti, "calu_crc", dummy_calu_crc_valid)
    monkeypatch.setattr(cu, "decrypt_aes", dummy_decrypt_aes)

    dummy_key = base64.b64encode(b"1234567890123456").decode("utf-8")
    ip_address = "192.168.1.10"
    api_endpoint = "api/info"

    result = await gti.async_get_thing_info(ip_address, dummy_key, api_endpoint)
    assert result == expected_status


@pytest.mark.asyncio
async def test_async_get_thing_info_empty_data(monkeypatch):
    async def dummy_async_send_http_request_empty(ip_address, port, request_str):
        body = base64.b64encode(b"").decode("utf-8")
        return ("dummy_headers", body)

    monkeypatch.setattr(
        gti, "async_send_http_request", dummy_async_send_http_request_empty
    )
    monkeypatch.setattr(gti, "calu_crc", dummy_calu_crc_valid)
    dummy_key = base64.b64encode(b"1234567890123456").decode("utf-8")
    ip_address = "192.168.1.10"
    api_endpoint = "api/info"
    result = await gti.async_get_thing_info(ip_address, dummy_key, api_endpoint)
    assert result is False


@pytest.mark.asyncio
async def test_async_get_thing_info_invalid_checksum(monkeypatch):
    monkeypatch.setattr(gti, "async_send_http_request", dummy_async_send_http_request)
    monkeypatch.setattr(gti, "calu_crc", dummy_calu_crc_invalid)
    dummy_key = base64.b64encode(b"1234567890123456").decode("utf-8")
    ip_address = "192.168.1.10"
    api_endpoint = "api/info"
    result = await gti.async_get_thing_info(ip_address, dummy_key, api_endpoint)
    assert result is False


@pytest.mark.asyncio
async def test_async_get_thing_info_json_decode_error(monkeypatch):
    # Test the async JSON decode error path (covering lines 82-126).
    monkeypatch.setattr(gti, "async_send_http_request", dummy_async_send_http_request)
    monkeypatch.setattr(gti, "calu_crc", dummy_calu_crc_valid)
    monkeypatch.setattr(cu, "decrypt_aes", lambda key, iv, data: b"not a json")
    dummy_key = base64.b64encode(b"1234567890123456").decode("utf-8")
    ip_address = "192.168.1.10"
    api_endpoint = "api/info"
    result = await gti.async_get_thing_info(ip_address, dummy_key, api_endpoint)
    assert result is False
