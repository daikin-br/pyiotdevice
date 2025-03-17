import base64
import importlib

import pytest

import pyiotdevice.crypto_utils as cu

# Import the send_ac_command module so we can patch its internal functions.
sac = importlib.import_module("pyiotdevice.send_ac_command")

# --- Shared Dummy Data and Functions ---

expected_status = {"status": "ok"}
expected_checksum = 12345  # 12345 in hex is 0x3039 (lower byte 0x39, higher byte 0x30)


# Dummy function to replace get_random_bytes
def dummy_get_random_bytes(n):
    return b"F" * n  # Fixed IV


# Dummy encryption: simply return a fixed dummy encrypted payload.
def dummy_encrypt_aes(aes_key, aes_iv, raw_data):
    return b"ENCRYPTED_PAYLOAD"


# Dummy decryption for success: return valid JSON bytes.
def dummy_decrypt_aes(aes_key, aes_iv, encrypted_data):
    return b'{"status": "ok"}'


# Dummy decryption for JSON error: return bytes that are not valid JSON.
def dummy_decrypt_aes_invalid_json(aes_key, aes_iv, encrypted_data):
    return b"not a json"


# Dummy checksum: always return expected_checksum.
def dummy_calu_crc_valid(init, data, length):
    return expected_checksum


# Dummy checksum: return an incorrect checksum.
def dummy_calu_crc_invalid(init, data, length):
    return expected_checksum + 1


# Dummy synchronous HTTP request for a valid response.
def dummy_send_http_request(ip_address, port, request_str, timeout=10):
    # Construct a packet:
    # - 16 bytes IV (fixed)
    # - 1 dummy separator byte (e.g. b'X')
    # - Dummy encrypted response (e.g. b'ENCRYPTED_RESP')
    # - 2 checksum bytes corresponding to expected_checksum (0x39, 0x30)
    fixed_iv = b"F" * 16
    dummy_sep = b"X"
    dummy_encrypted_response = b"ENCRYPTED_RESP"
    packet = fixed_iv + dummy_sep + dummy_encrypted_response + b"\x39\x30"
    body = base64.b64encode(packet).decode("utf-8")
    return ("dummy_headers", body)


# Dummy synchronous HTTP request that returns empty data.
def dummy_send_http_request_empty(ip_address, port, request_str, timeout=10):
    body = base64.b64encode(b"").decode("utf-8")
    return ("dummy_headers", body)


# Dummy synchronous HTTP request with invalid checksum (simulate checksum failure).
def dummy_send_http_request_invalid_checksum(ip_address, port, request_str, timeout=10):
    fixed_iv = b"F" * 16
    dummy_sep = b"X"
    dummy_encrypted_response = b"ENCRYPTED_RESP"
    # Append wrong checksum bytes.
    packet = fixed_iv + dummy_sep + dummy_encrypted_response + b"\x00\x00"
    body = base64.b64encode(packet).decode("utf-8")
    return ("dummy_headers", body)


# Dummy asynchronous HTTP request for a valid response.
async def dummy_async_send_http_request(ip_address, port, request_str, timeout=10):
    fixed_iv = b"F" * 16
    dummy_sep = b"X"
    dummy_encrypted_response = b"ENCRYPTED_RESP"
    packet = fixed_iv + dummy_sep + dummy_encrypted_response + b"\x39\x30"
    body = base64.b64encode(packet).decode("utf-8")
    return ("dummy_headers", body)


# Dummy asynchronous HTTP request that returns empty data.
async def dummy_async_send_http_request_empty(
    ip_address, port, request_str, timeout=10
):
    body = base64.b64encode(b"").decode("utf-8")
    return ("dummy_headers", body)


# Dummy asynchronous HTTP request with invalid checksum.
async def dummy_async_send_http_request_invalid_checksum(
    ip_address, port, request_str, timeout=10
):
    fixed_iv = b"F" * 16
    dummy_sep = b"X"
    dummy_encrypted_response = b"ENCRYPTED_RESP"
    packet = fixed_iv + dummy_sep + dummy_encrypted_response + b"\x00\x00"
    body = base64.b64encode(packet).decode("utf-8")
    return ("dummy_headers", body)


# --- Synchronous Tests for send_operation_data ---


def test_send_operation_data_success(monkeypatch):
    # Patch the functions in send_ac_command to simulate a successful command send.
    monkeypatch.setattr(sac, "get_random_bytes", dummy_get_random_bytes)
    monkeypatch.setattr(sac, "encrypt_aes", dummy_encrypt_aes)
    monkeypatch.setattr(cu, "decrypt_aes", dummy_decrypt_aes)
    monkeypatch.setattr(sac, "calu_crc", dummy_calu_crc_valid)
    monkeypatch.setattr(sac, "send_http_request", dummy_send_http_request)

    dummy_key = base64.b64encode(b"1234567890123456").decode("utf-8")
    ip_address = "192.168.1.10"
    data = '{"port1":{"temperature":22}}'
    command_suffix = "_CMD"

    result = sac.send_operation_data(ip_address, dummy_key, data, command_suffix)
    assert result == expected_status


def test_send_operation_data_empty_response(monkeypatch):
    # Simulate an empty HTTP response.
    monkeypatch.setattr(sac, "get_random_bytes", dummy_get_random_bytes)
    monkeypatch.setattr(sac, "encrypt_aes", dummy_encrypt_aes)
    monkeypatch.setattr(sac, "send_http_request", dummy_send_http_request_empty)
    monkeypatch.setattr(sac, "calu_crc", dummy_calu_crc_valid)

    dummy_key = base64.b64encode(b"1234567890123456").decode("utf-8")
    ip_address = "192.168.1.10"
    data = '{"port1":{"temperature":22}}'
    command_suffix = "_CMD"

    result = sac.send_operation_data(ip_address, dummy_key, data, command_suffix)
    # Expect None because an empty response triggers an exception.
    assert result is None


def test_send_operation_data_invalid_checksum(monkeypatch):
    # Simulate a response with invalid checksum.
    monkeypatch.setattr(sac, "get_random_bytes", dummy_get_random_bytes)
    monkeypatch.setattr(sac, "encrypt_aes", dummy_encrypt_aes)
    monkeypatch.setattr(cu, "decrypt_aes", dummy_decrypt_aes)
    monkeypatch.setattr(sac, "calu_crc", dummy_calu_crc_valid)
    monkeypatch.setattr(
        sac, "send_http_request", dummy_send_http_request_invalid_checksum
    )

    dummy_key = base64.b64encode(b"1234567890123456").decode("utf-8")
    ip_address = "192.168.1.10"
    data = '{"port1":{"temperature":22}}'
    command_suffix = "_CMD"

    result = sac.send_operation_data(ip_address, dummy_key, data, command_suffix)
    # Expect None because checksum validation fails.
    assert result is None


def test_send_operation_data_json_decode_error(monkeypatch):
    # Simulate a JSON decode error by forcing decrypt_aes to return invalid JSON.
    monkeypatch.setattr(sac, "get_random_bytes", dummy_get_random_bytes)
    monkeypatch.setattr(sac, "encrypt_aes", dummy_encrypt_aes)
    monkeypatch.setattr(cu, "decrypt_aes", dummy_decrypt_aes_invalid_json)
    monkeypatch.setattr(sac, "calu_crc", dummy_calu_crc_valid)
    monkeypatch.setattr(sac, "send_http_request", dummy_send_http_request)

    dummy_key = base64.b64encode(b"1234567890123456").decode("utf-8")
    ip_address = "192.168.1.10"
    data = '{"port1":{"temperature":22}}'
    command_suffix = "_CMD"

    result = sac.send_operation_data(ip_address, dummy_key, data, command_suffix)
    # Expect None because the decrypted data is not valid JSON.
    assert result is None


# --- Asynchronous Tests for async_send_operation_data ---


@pytest.mark.asyncio
async def test_async_send_operation_data_success(monkeypatch):
    monkeypatch.setattr(sac, "get_random_bytes", dummy_get_random_bytes)
    monkeypatch.setattr(sac, "encrypt_aes", dummy_encrypt_aes)
    monkeypatch.setattr(cu, "decrypt_aes", dummy_decrypt_aes)
    monkeypatch.setattr(sac, "calu_crc", dummy_calu_crc_valid)
    monkeypatch.setattr(sac, "async_send_http_request", dummy_async_send_http_request)

    dummy_key = base64.b64encode(b"1234567890123456").decode("utf-8")
    ip_address = "192.168.1.10"
    data = '{"port1":{"temperature":22}}'
    command_suffix = "_CMD"

    result = await sac.async_send_operation_data(
        ip_address, dummy_key, data, command_suffix
    )
    assert result == expected_status


@pytest.mark.asyncio
async def test_async_send_operation_data_empty_response(monkeypatch):
    monkeypatch.setattr(sac, "get_random_bytes", dummy_get_random_bytes)
    monkeypatch.setattr(sac, "encrypt_aes", dummy_encrypt_aes)
    monkeypatch.setattr(
        sac, "async_send_http_request", dummy_async_send_http_request_empty
    )
    monkeypatch.setattr(sac, "calu_crc", dummy_calu_crc_valid)

    dummy_key = base64.b64encode(b"1234567890123456").decode("utf-8")
    ip_address = "192.168.1.10"
    data = '{"port1":{"temperature":22}}'
    command_suffix = "_CMD"

    result = await sac.async_send_operation_data(
        ip_address, dummy_key, data, command_suffix
    )
    assert result is None


@pytest.mark.asyncio
async def test_async_send_operation_data_invalid_checksum(monkeypatch):
    monkeypatch.setattr(sac, "get_random_bytes", dummy_get_random_bytes)
    monkeypatch.setattr(sac, "encrypt_aes", dummy_encrypt_aes)
    monkeypatch.setattr(cu, "decrypt_aes", dummy_decrypt_aes)
    monkeypatch.setattr(sac, "calu_crc", dummy_calu_crc_valid)
    monkeypatch.setattr(
        sac, "async_send_http_request", dummy_async_send_http_request_invalid_checksum
    )

    dummy_key = base64.b64encode(b"1234567890123456").decode("utf-8")
    ip_address = "192.168.1.10"
    data = '{"port1":{"temperature":22}}'
    command_suffix = "_CMD"

    result = await sac.async_send_operation_data(
        ip_address, dummy_key, data, command_suffix
    )
    assert result is None


@pytest.mark.asyncio
async def test_async_send_operation_data_json_decode_error(monkeypatch):
    monkeypatch.setattr(sac, "get_random_bytes", dummy_get_random_bytes)
    monkeypatch.setattr(sac, "encrypt_aes", dummy_encrypt_aes)
    monkeypatch.setattr(cu, "decrypt_aes", dummy_decrypt_aes_invalid_json)
    monkeypatch.setattr(sac, "calu_crc", dummy_calu_crc_valid)
    monkeypatch.setattr(sac, "async_send_http_request", dummy_async_send_http_request)

    dummy_key = base64.b64encode(b"1234567890123456").decode("utf-8")
    ip_address = "192.168.1.10"
    data = '{"port1":{"temperature":22}}'
    command_suffix = "_CMD"

    result = await sac.async_send_operation_data(
        ip_address, dummy_key, data, command_suffix
    )
    assert result is None
