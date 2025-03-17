"""
This module provides socket utilities for the pyiotdevice library.

It includes functions to send raw requests over a TCP connection,
parse the responses, and handle errors such as invalid data or timeouts.
"""

import asyncio
import logging
import socket

from .custom_exceptions import InvalidDataException

_LOGGER = logging.getLogger(__name__)

# Define default port for ac communication
DEFAULT_PORT = 15914


def check_not_found_case(response: str) -> bool:
    """
    Check if the response indicates a 'not found' case.

    Args:
        response (str): The HTTP response string.

    Returns:
        bool: True if the response does not contain "404 Not Found", False otherwise.
    """
    return "404 Not Found" not in response


def send_http_request(
    ip_address: str, port: int = DEFAULT_PORT, request_str: str = "", timeout: int = 20
):
    """
    Send an HTTP request over a TCP connection and return the parsed response.

    Args:
        ip_address (str): The IP address of the server.
        port (int): The port to connect to.
        request_str (str): The HTTP request string.
        timeout (int): The connection timeout in seconds (default is 20).

    Returns:
        tuple: A tuple containing the headers (str) and body (str) of the HTTP response.

    Raises:
        InvalidDataException: For 404 status code or has an invalid format.
        Exception: For other unexpected errors during the connection.
    """
    try:
        # Open a TCP connection
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            _LOGGER.debug("Connecting to %s:%s...", ip_address, port)
            client.connect((ip_address, port))

            # Send the HTTP request
            logging.debug("Sending request...")
            client.sendall(request_str.encode("utf-8"))

            # Receive the response
            _LOGGER.debug("Receiving response...")
            response_data = client.recv(1024).decode("utf-8")

        # Check if the response indicates a "not found" case
        if not check_not_found_case(response_data):
            _LOGGER.debug("Received 404 Not Found in response.")
            raise InvalidDataException()

        # Parse the response
        response_parts = response_data.split("\r\n\r\n")
        if len(response_parts) < 2:
            _LOGGER.debug("Invalid HTTP response format.")
            raise InvalidDataException()

        headers, body = response_parts[0], response_parts[1]

        return headers, body

    except socket.timeout:
        _LOGGER.debug("Connection to %s:%s timed out.", ip_address, port)
        raise
    except Exception as e:
        _LOGGER.debug("Error sending request to %s:%s: %s", ip_address, port, e)
        raise


async def async_send_http_request(
    ip_address: str, port: int = DEFAULT_PORT, request_str: str = "", timeout: int = 20
):
    """
    Asynchronously send an HTTP request over a TCP connection.

    Args:
        ip_address (str): The IP address of the server.
        port (int): The port to connect to.
        request_str (str): The HTTP request string.
        timeout (int): The connection timeout in seconds (default is 20).

    Returns:
        tuple: A tuple containing the headers (str) and body (str) of the HTTP response.

    Raises:
        InvalidDataException: For 404 status code and Invalid format.
        Exception: For other unexpected errors.
    """
    try:
        _LOGGER.debug("Connecting to %s:%s...", ip_address, port)
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip_address, port), timeout
        )

        _LOGGER.debug("Sending request...")
        writer.write(request_str.encode("utf-8"))
        await writer.drain()

        _LOGGER.debug("Receiving response...")
        response_data = await asyncio.wait_for(reader.read(1024), timeout)

        writer.close()
        await writer.wait_closed()

        response_text = response_data.decode("utf-8")

        # Check if the response indicates a "not found" case
        if not check_not_found_case(response_text):
            _LOGGER.debug("Received 404 Not Found in response.")
            raise InvalidDataException()

        # Parse the response by splitting headers and body
        response_parts = response_text.split("\r\n\r\n")
        if len(response_parts) < 2:
            _LOGGER.debug("Invalid HTTP response format.")
            raise InvalidDataException()

        headers, body = response_parts[0], response_parts[1]
        return headers, body

    except asyncio.TimeoutError:
        _LOGGER.debug("Connection to %s:%s timed out.", ip_address, port)
        raise
    except Exception as e:
        _LOGGER.debug("Error sending request to %s:%s: %s", ip_address, port, e)
        raise
