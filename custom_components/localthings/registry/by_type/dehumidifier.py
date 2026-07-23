"""Read-only Samsung dehumidifier device registry."""
from ..capabilities import common, dehumidifier, ignored
from ._base import DeviceRegistry, _build


REGISTRY = DeviceRegistry(
    name='dehumidifier',
    capabilities=_build([
        *ignored.IGNORED,
        # These common capabilities are read-only on the captured model.
        common.ENERGY_METER,
        common.FIRMWARE_UPDATE,
        common.REMOTE_CONTROL_GENERIC,
        common.REMOTE_CONTROL_VS_FALLBACK,
        dehumidifier.POWER_STATE,
        dehumidifier.MODE_STATE,
        dehumidifier.HUMIDITY_STATE,
        dehumidifier.AIR_FILTER,
        dehumidifier.ALARMS,
        dehumidifier.AUTO_CLEAN_STATE,
        *dehumidifier.COVERAGE,
    ]),
)
