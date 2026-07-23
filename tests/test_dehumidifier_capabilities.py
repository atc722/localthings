"""Tests for read-only Samsung dehumidifier support."""
from custom_components.localthings.registry.adapter import flatten
from custom_components.localthings.registry.by_type import (
    for_device,
    for_device_by_model,
)
from custom_components.localthings.registry.by_type import dehumidifier
from custom_components.localthings.registry.capabilities import (
    dehumidifier as capabilities,
)
from custom_components.localthings.registry.discovery import discover
from custom_components.localthings.registry.entities import (
    BinarySensorDesc,
    SensorDesc,
)
from tests.conftest import _load_device


def _bound_and_state():
    resources = _load_device('dehumidifier')
    bound = discover(
        resources,
        dehumidifier.REGISTRY.capabilities,
        dehumidifier.REGISTRY.pattern_capabilities,
    )
    return resources, bound, flatten(bound, resources)


def test_dehumidifier_resolves_by_one_ui_name():
    registry = for_device('7.0 Dehumidifier')
    assert registry is dehumidifier.REGISTRY


def test_dehumidifier_resolves_by_dhm_model_token():
    registry = for_device_by_model(
        'TP1X_DA_AC_DHM_01001_0000|10253841|'
        '77000000001700000A00000000000000',
        'TP1X_DA_AC_DHM_01001_0000',
    )
    assert registry is dehumidifier.REGISTRY


def test_dehumidifier_entities_are_strictly_read_only():
    _, bound, _ = _bound_and_state()
    assert bound
    assert all(
        isinstance(item.desc, (SensorDesc, BinarySensorDesc))
        for item in bound
    )
    assert not any(hasattr(item.desc, 'write_fn') for item in bound)


def test_dehumidifier_fixture_reads_observed_state():
    _, _, state = _bound_and_state()
    assert state['power'] is False
    assert state['mode'] == 'High'
    # SmartThings currentHumidity matches fivepercentHumidity (67), not the
    # separate raw internal humidity field (72), on the captured device.
    assert state['current_humidity'] == 67.0
    assert state['target_humidity'] == 60.0
    assert state['air_filter_usage'] == 14
    assert state['air_filter_status'] == 'normal'
    assert state['water_tank_full'] is False
    assert state['alarm_code'] == 'none'
    assert state['auto_clean_enabled'] is True
    assert state['auto_clean_status'] == 'Stop'


def test_water_tank_alarm_ignores_deleted_off_record():
    items = [
        {
            'x.com.samsung.da.code': 'WaterTankFull_OFF',
            'x.com.samsung.da.state': 'Deleted',
        }
    ]
    assert capabilities._water_tank_full(items) is False
    assert capabilities._active_alarm_codes(items) == 'none'


def test_water_tank_alarm_reports_active_record():
    items = [
        {
            'x.com.samsung.da.code': 'WaterTankFull_ON',
            'x.com.samsung.da.state': 'Occurred',
        }
    ]
    assert capabilities._water_tank_full(items) is True
    assert capabilities._active_alarm_codes(items) == 'WaterTankFull_ON'
