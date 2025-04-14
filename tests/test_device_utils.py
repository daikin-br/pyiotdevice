from pyiotdevice.device_utils import (
    get_fan_mode_value,
    get_hvac_mode_value,
    map_fan_speed,
    map_hvac_mode,
    prepare_device_payload,
    validate_temperature,
)


def test_get_fan_mode_value():
    # Test that known HA fan modes return the corresponding device values.
    assert get_fan_mode_value("auto") == 17
    assert get_fan_mode_value("high") == 7
    assert get_fan_mode_value("medium_high") == 6
    # Test unknown fan mode returns None.
    assert get_fan_mode_value("invalid_mode") is None


def test_get_hvac_mode_value():
    # Test that HVAC mode string (in any case) returns the correct device value.
    assert get_hvac_mode_value("cool") == 3
    assert get_hvac_mode_value("COOL") == 3
    assert get_hvac_mode_value("fan_only") == 6
    # Test unknown hvac mode returns None.
    assert get_hvac_mode_value("unknown") is None


def test_map_fan_speed():
    # Test that known device fan speed values return the correct HA fan mode strings.
    assert map_fan_speed(7) == "high"
    assert map_fan_speed(17) == "auto"
    # Test unknown value returns default "auto".
    assert map_fan_speed(999) == "auto"


def test_map_hvac_mode():
    # Test that known device HVAC mode values return the correct HA HVAC mode strings.
    assert map_hvac_mode(3) == "cool"
    assert map_hvac_mode(0) == "off"
    # Test unknown value returns default "off".
    assert map_hvac_mode(999) == "off"


def test_prepare_device_payload():
    # Test preparing a simple payload.
    payload = prepare_device_payload(temperature=22)
    expected = {"port1": {"temperature": 22}}
    assert payload == expected

    # Test preparing a payload with multiple keyword arguments.
    payload = prepare_device_payload(temperature=22, fan=7)
    expected = {"port1": {"temperature": 22, "fan": 7}}
    assert payload == expected

    # Test when fan is not provided:
    payload = prepare_device_payload(mode=2)
    expected = {"port1": {"mode": 2, "fan": 17}}
    assert payload == expected

    # Test when fan is provided, it should still be overridden:
    payload = prepare_device_payload(mode=2, fan=999)
    expected = {"port1": {"mode": 2, "fan": 17}}
    assert payload == expected


def test_validate_temperature():
    # Valid integer input
    assert validate_temperature(20) == 20

    # Valid float input (should be truncated to int)
    assert validate_temperature(20.7) == 20

    # Below minimum (should return default)
    assert validate_temperature(10, min_temp=16, max_temp=32, default_temp=24) == 24

    # Above maximum (should return default)
    assert validate_temperature(40, min_temp=16, max_temp=32, default_temp=24) == 24

    # Invalid type (string) -> should return default
    assert validate_temperature("hot", default_temp=24) == 24

    # Edge case: exactly at min
    assert validate_temperature(16, min_temp=16, max_temp=32, default_temp=24) == 16

    # Edge case: exactly at max
    assert validate_temperature(32, min_temp=16, max_temp=32, default_temp=24) == 32
