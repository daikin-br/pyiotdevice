"""
This module defines custom exceptions used in the pyiotdevice library.

Such as CommunicationErrorException and InvalidDataException.
"""


class CommunicationErrorException(Exception):
    """Raised when there is a communication error in the network request."""

    def __str__(self):
        return "Communication error occurred."


class InvalidDataException(Exception):
    """Raised when invalid data is received or the response format is incorrect."""

    def __str__(self):
        return "Invalid Data."
