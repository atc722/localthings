"""Read-only capabilities for Samsung dehumidifiers.

The first supported model (TP1X_DA_AC_DHM_01001_0000) was verified from a
live, authenticated /device/0 response.  This module intentionally exposes
only observed state.  It does not reuse common.POWER or model mode/target
humidity as switch/select/number entities because no write payload has been
round-trip tested on the appliance yet.
"""
from ..capability import Capability
from ..entities import BinarySensorDesc, SensorDesc


MODE_OPTIONS = (
    'Smart',
    'Max',
    'High',
    'Medium',
    'Quiet',
    'ClothesDrying',
)

AUTO_CLEAN_STATUS_OPTIONS = ('Start', 'TimedClean', 'Stop')


def _num(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _first(value):
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def _filter_usage_percent(rep):
    used = _num(rep.get('x.com.samsung.da.filterUsage'))
    capacity = _num(rep.get('x.com.samsung.da.filterCapacity'))
    if used is None or not capacity:
        return None
    return round(used / capacity * 100)


def _is_active_alarm(item):
    if not isinstance(item, dict):
        return False
    code = str(item.get('x.com.samsung.da.code') or '')
    state = str(item.get('x.com.samsung.da.state') or '')
    return bool(code) and not code.endswith('_OFF') and state.lower() != 'deleted'


def _active_alarm_codes(items):
    if not isinstance(items, list):
        return 'none'
    codes = [
        item.get('x.com.samsung.da.code')
        for item in items
        if _is_active_alarm(item)
    ]
    return ', '.join(codes) if codes else 'none'


def _water_tank_full(items):
    if not isinstance(items, list):
        return False
    return any(
        str(item.get('x.com.samsung.da.code') or '').startswith('WaterTankFull')
        and _is_active_alarm(item)
        for item in items
        if isinstance(item, dict)
    )


POWER_STATE = Capability(
    href='/power/vs/0',
    poll_tier='hot',
    entities=(
        BinarySensorDesc(
            key='power',
            field='x.com.samsung.da.power',
            name='Power',
            device_class='power',
            value_fn=lambda value: value == 'On',
        ),
    ),
)

MODE_STATE = Capability(
    href='/mode/vs/0',
    poll_tier='hot',
    entities=(
        SensorDesc(
            key='mode',
            field='x.com.samsung.da.modes',
            name='Mode',
            device_class='enum',
            options=MODE_OPTIONS,
            icon='mdi:air-humidifier-off',
            value_fn=_first,
        ),
    ),
)

HUMIDITY_STATE = Capability(
    href='/humidity/vs/0',
    poll_tier='hot',
    entities=(
        # fivepercentHumidity is the value Samsung publishes as
        # currentHumidity through SmartThings on this model.  The separate
        # raw `humidity` field is deliberately not surfaced as a second,
        # conflicting room-humidity sensor.
        SensorDesc(
            key='current_humidity',
            field='x.com.samsung.da.fivepercentHumidity',
            name='Current humidity',
            device_class='humidity',
            state_class='measurement',
            unit='%',
            value_fn=_num,
        ),
        SensorDesc(
            key='target_humidity',
            field='x.com.samsung.da.desiredHumidity',
            name='Target humidity',
            unit='%',
            icon='mdi:water-percent',
            value_fn=_num,
        ),
    ),
)

AIR_FILTER = Capability(
    href='/filter/airdustfilter/vs/0',
    poll_tier='cold',
    entities=(
        SensorDesc(
            key='air_filter_usage',
            rep_fn=_filter_usage_percent,
            name='Filter usage',
            unit='%',
            state_class='measurement',
            icon='mdi:air-filter',
            entity_category='diagnostic',
        ),
        SensorDesc(
            key='air_filter_status',
            field='x.com.samsung.da.filterStatus',
            name='Filter status',
            device_class='enum',
            options=('normal', 'wash', 'replace'),
            icon='mdi:air-filter',
            entity_category='diagnostic',
            value_fn=lambda value: value.lower() if isinstance(value, str) else value,
        ),
    ),
)

ALARMS = Capability(
    href='/alarms/vs/0',
    poll_tier='hot',
    entities=(
        BinarySensorDesc(
            key='water_tank_full',
            field='x.com.samsung.da.items',
            name='Water tank full',
            device_class='problem',
            value_fn=_water_tank_full,
        ),
        SensorDesc(
            key='alarm_code',
            field='x.com.samsung.da.items',
            name='Alarm code',
            icon='mdi:alert',
            entity_category='diagnostic',
            value_fn=_active_alarm_codes,
        ),
    ),
)

AUTO_CLEAN_STATE = Capability(
    href='/option/autoclean/vs/0',
    poll_tier='warm',
    entities=(
        BinarySensorDesc(
            key='auto_clean_enabled',
            field='x.com.samsung.da.settingStatus',
            name='Auto clean enabled',
            value_fn=lambda value: value in ('On', 'TimedClean'),
        ),
        SensorDesc(
            key='auto_clean_status',
            field='x.com.samsung.da.status',
            name='Auto clean status',
            device_class='enum',
            options=AUTO_CLEAN_STATUS_OPTIONS,
            icon='mdi:air-filter',
        ),
    ),
)


# Appliance-specific resources that carry static metadata, opaque scheduling
# blobs, an empty rep, or state whose semantics are not sufficiently proven to
# expose.  Keeping these covered preserves meaningful capability-gap reporting.
_COVERED_HREFS = (
    '/availablecontrolsets/vs/0',
    '/da/softreset/vs/0',
    '/keepnormalstate/vs/0',
    '/mode/convenient/vs/0',
    '/option/muteonce/vs/0',
    '/personality/presence/vs/0',
    '/reserverulesets/vs/0',
    '/sensors/vs/0',
    '/welcome/humidity/vs/0',
)

COVERAGE = tuple(Capability(href=href) for href in _COVERED_HREFS)
