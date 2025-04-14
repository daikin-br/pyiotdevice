"""
Device utilities for pyiotdevice.

This module defines a mapping between Home Assistant mode strings and device-specific
mode values. It provides a helper function, to retrieve the
corresponding mode value for a given Home Assistant mode and vice versa.
It also provides generic device specific helper functions.


"""

from typing import Optional, Union

# Mapping of device HVAC mode values to HA HVAC mode strings.
DAIKIN_TO_HA_HVAC_MODE_MAPPING = {
    0: "off",
    6: "fan_only",
    3: "cool",
    2: "dry",
    4: "heat",
    1: "auto",
}

# Reverse mapping of generic HVAC mode strings to device-specific HVAC mode values.
HA_TO_DAIKIN_HVAC_MODE_MAPPING = {
    "off": 0,
    "fan_only": 6,
    "cool": 3,
    "dry": 2,
    "heat": 4,
    "auto": 1,
}

# Mapping of device (Daikin) fan speed values to Home Assistant fan mode strings.
DAIKIN_TO_HA_FAN_SPEED_MAPPING = {
    17: "auto",
    7: "high",
    6: "medium_high",
    5: "medium",
    4: "low_medium",
    3: "low",
    18: "quiet",
}

# Reverse mapping: Home Assistant fan mode strings to device (Daikin) fan speed values.
HA_TO_DAIKIN_FAN_SPEED_MAPPING = {
    "auto": 17,
    "high": 7,
    "medium_high": 6,
    "medium": 5,
    "low_medium": 4,
    "low": 3,
    "quiet": 18,
}


def get_fan_mode_value(fan_mode: str) -> Optional[int]:
    """Return the device-specific fan mode value for the given HA fan mode."""
    return HA_TO_DAIKIN_FAN_SPEED_MAPPING.get(fan_mode)


def get_hvac_mode_value(hvac_mode: str) -> Optional[int]:
    """Return the device-specific HVAC mode value for a given HA HVAC mode string."""
    return HA_TO_DAIKIN_HVAC_MODE_MAPPING.get(hvac_mode.lower())


def map_fan_speed(fan_value: int) -> str:
    """Return the corresponding HA fan mode string. Defaults to "auto"."""
    return DAIKIN_TO_HA_FAN_SPEED_MAPPING.get(fan_value, "auto")


def map_hvac_mode(hvac_value: int) -> str:
    """Return the HA HVAC mode string Default to "off"."""
    return DAIKIN_TO_HA_HVAC_MODE_MAPPING.get(hvac_value, "off")


def prepare_device_payload(**kwargs) -> dict:
    """Prepare payload dictionary for device communication."""
    # Copy the provided keyword arguments
    payload = dict(kwargs)

    mode_value = HA_TO_DAIKIN_HVAC_MODE_MAPPING.get("dry")
    if payload.get("mode") == mode_value:
        payload["fan"] = HA_TO_DAIKIN_FAN_SPEED_MAPPING.get("auto")

    return {"port1": payload}


def validate_temperature(
    temperature_value: Optional[Union[float, int]],
    min_temp: float = 10.0,
    max_temp: float = 32.0,
    default_temp: int = 24,
) -> int:
    """Validate and return a temperature value within the allowed range.

    Args:
        temperature_value (Optional[Union[float, int]]): The temperature to validate.
        min_temp (float): Minimum allowed temperature.
        max_temp (float): Maximum allowed temperature.
        default_temp (int): Default fallback temperature.

    Returns:
        int: A valid temperature value.
    """
    if isinstance(temperature_value, (int, float)):
        if min_temp <= temperature_value <= max_temp:
            return int(temperature_value)
    return default_temp
