import asyncio
import importlib
import socket

import pytest

from pyiotdevice.custom_exceptions import InvalidDataException

# Import the socket_utils module to test its functions.
su = importlib.import_module("pyiotdevice.socket_utils")

# --- Tests for check_not_found_case ---


def test_check_not_found_case():
    assert su.check_not_found_case("HTTP/1.1 200 OK\r\n\r\nBody") is True
    assert su.check_not_found_case("HTTP/1.1 404 Not Found\r\n\r\nBody") is False


# --- Dummy Socket for Synchronous Tests ---


class DummySocket:
    def __init__(
        self,
        response_bytes,
        raise_on_recv=False,
        raise_on_connect=False,
        raise_on_sendall=False,
    ):
        self.response_bytes = response_bytes
        self.raise_on_recv = raise_on_recv
        self.raise_on_connect = raise_on_connect
        self.raise_on_sendall = raise_on_sendall
        self.sent_data = b""

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, address):
        if self.raise_on_connect:
            raise Exception("connect error")

    def sendall(self, data):
        if self.raise_on_sendall:
            raise Exception("sendall error")
        self.sent_data += data

    def recv(self, bufsize):
        if self.raise_on_recv:
            raise socket.timeout("timeout")
        return self.response_bytes

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


# --- Synchronous Tests for send_http_request ---


def test_send_http_request_success(monkeypatch):
    # Create a valid HTTP response:
    # e.g. "HTTP/1.1 200 OK\r\nHeader: value\r\n\r\nBody"
    response_text = "HTTP/1.1 200 OK\r\nHeader: value\r\n\r\nBody"
    response_bytes = response_text.encode("utf-8")

    # Patch socket.socket to return our DummySocket.
    monkeypatch.setattr(
        socket, "socket", lambda *args, **kwargs: DummySocket(response_bytes)
    )

    headers, body = su.send_http_request(
        "127.0.0.1", su.DEFAULT_PORT, "GET / HTTP/1.1\r\n\r\n", timeout=5
    )
    assert headers == "HTTP/1.1 200 OK\r\nHeader: value"
    assert body == "Body"


def test_send_http_request_not_found(monkeypatch):
    # Response that contains "404 Not Found"
    response_text = "HTTP/1.1 404 Not Found\r\nHeader: value\r\n\r\nBody"
    response_bytes = response_text.encode("utf-8")

    monkeypatch.setattr(
        socket, "socket", lambda *args, **kwargs: DummySocket(response_bytes)
    )

    with pytest.raises(InvalidDataException):
        su.send_http_request(
            "127.0.0.1", su.DEFAULT_PORT, "GET / HTTP/1.1\r\n\r\n", timeout=5
        )


def test_send_http_request_invalid_format(monkeypatch):
    # Response that does not contain the required "\r\n\r\n" separator.
    response_text = "HTTP/1.1 200 OK\r\nHeader: value"  # Missing body separator
    response_bytes = response_text.encode("utf-8")

    monkeypatch.setattr(
        socket, "socket", lambda *args, **kwargs: DummySocket(response_bytes)
    )

    with pytest.raises(InvalidDataException):
        su.send_http_request(
            "127.0.0.1", su.DEFAULT_PORT, "GET / HTTP/1.1\r\n\r\n", timeout=5
        )


def test_send_http_request_timeout(monkeypatch):
    # Simulate a timeout by having recv raise socket.timeout.
    response_bytes = b""
    monkeypatch.setattr(
        socket,
        "socket",
        lambda *args, **kwargs: DummySocket(response_bytes, raise_on_recv=True),
    )

    with pytest.raises(socket.timeout):
        su.send_http_request(
            "127.0.0.1", su.DEFAULT_PORT, "GET / HTTP/1.1\r\n\r\n", timeout=5
        )


def test_send_http_request_generic_exception(monkeypatch):
    # Simulate an exception during connect.
    monkeypatch.setattr(
        socket,
        "socket",
        lambda *args, **kwargs: DummySocket(b"", raise_on_connect=True),
    )

    with pytest.raises(Exception):
        su.send_http_request(
            "127.0.0.1", su.DEFAULT_PORT, "GET / HTTP/1.1\r\n\r\n", timeout=5
        )


# --- Asynchronous Tests for async_send_http_request ---


# Dummy classes for async reader/writer.
class DummyReader:
    def __init__(self, response_bytes, raise_on_read=False):
        self.response_bytes = response_bytes
        self.raise_on_read = raise_on_read

    async def read(self, n):
        if self.raise_on_read:
            raise asyncio.TimeoutError("timeout")
        return self.response_bytes


class DummyWriter:
    def __init__(self):
        self.data = b""

    def write(self, data):
        self.data += data

    async def drain(self):
        pass

    def close(self):
        pass

    async def wait_closed(self):
        pass


# Dummy open_connection to simulate a successful connection.
async def dummy_open_connection_success(ip, port):
    # Return a DummyReader with valid response and a DummyWriter.
    response_text = "HTTP/1.1 200 OK\r\nHeader: value\r\n\r\nBody"
    response_bytes = response_text.encode("utf-8")
    return DummyReader(response_bytes), DummyWriter()


# Dummy open_connection for "404 Not Found"
async def dummy_open_connection_not_found(ip, port):
    response_text = "HTTP/1.1 404 Not Found\r\nHeader: value\r\n\r\nBody"
    response_bytes = response_text.encode("utf-8")
    return DummyReader(response_bytes), DummyWriter()


# Dummy open_connection for invalid format.
async def dummy_open_connection_invalid_format(ip, port):
    response_text = "HTTP/1.1 200 OK\r\nHeader: value"  # Missing separator
    response_bytes = response_text.encode("utf-8")
    return DummyReader(response_bytes), DummyWriter()


# Dummy open_connection for timeout: raise asyncio.TimeoutError
async def dummy_open_connection_timeout(ip, port):
    raise asyncio.TimeoutError("timeout")


@pytest.mark.asyncio
async def test_async_send_http_request_success(monkeypatch):
    monkeypatch.setattr(asyncio, "open_connection", dummy_open_connection_success)

    headers, body = await su.async_send_http_request(
        "127.0.0.1", su.DEFAULT_PORT, "GET / HTTP/1.1\r\n\r\n", timeout=5
    )
    assert headers == "HTTP/1.1 200 OK\r\nHeader: value"
    assert body == "Body"


@pytest.mark.asyncio
async def test_async_send_http_request_not_found(monkeypatch):
    monkeypatch.setattr(asyncio, "open_connection", dummy_open_connection_not_found)

    with pytest.raises(InvalidDataException):
        await su.async_send_http_request(
            "127.0.0.1", su.DEFAULT_PORT, "GET / HTTP/1.1\r\n\r\n", timeout=5
        )


@pytest.mark.asyncio
async def test_async_send_http_request_invalid_format(monkeypatch):
    monkeypatch.setattr(
        asyncio, "open_connection", dummy_open_connection_invalid_format
    )

    with pytest.raises(InvalidDataException):
        await su.async_send_http_request(
            "127.0.0.1", su.DEFAULT_PORT, "GET / HTTP/1.1\r\n\r\n", timeout=5
        )


@pytest.mark.asyncio
async def test_async_send_http_request_timeout(monkeypatch):
    monkeypatch.setattr(asyncio, "open_connection", dummy_open_connection_timeout)

    with pytest.raises(asyncio.TimeoutError):
        await su.async_send_http_request(
            "127.0.0.1", su.DEFAULT_PORT, "GET / HTTP/1.1\r\n\r\n", timeout=5
        )
