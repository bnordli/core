"""Constants for the Plejd integration."""

DOMAIN = "plejd"

CONF_CRYPTO_KEY = "crypto_key"
CONF_DISCOVERY_TIMEOUT = "discovery_timeout"
CONF_DBUS_ADDRESS = "dbus_address"
CONF_OFFSET_MINUTES = "offset_minutes"

DEFAULT_DISCOVERY_TIMEOUT = 2
DEFAULT_DBUS_PATH = "unix:path=/run/dbus/system_bus_socket"
TIME_DELTA_SYNC = 60  # if delta is more than a minute, sync time

DATA_PLEJD = "plejdObject"

BLUEZ_SERVICE_NAME = "org.bluez"
DBUS_OM_IFACE = "org.freedesktop.DBus.ObjectManager"
DBUS_PROP_IFACE = "org.freedesktop.DBus.Properties"

BLUEZ_ADAPTER_IFACE = "org.bluez.Adapter1"
BLUEZ_DEVICE_IFACE = "org.bluez.Device1"
GATT_SERVICE_IFACE = "org.bluez.GattService1"
GATT_CHRC_IFACE = "org.bluez.GattCharacteristic1"

PLEJD_SVC_UUID = "31ba0001-6085-4726-be45-040c957391b5"
PLEJD_LIGHTLEVEL_UUID = "31ba0003-6085-4726-be45-040c957391b5"
PLEJD_DATA_UUID = "31ba0004-6085-4726-be45-040c957391b5"
PLEJD_LAST_DATA_UUID = "31ba0005-6085-4726-be45-040c957391b5"
PLEJD_AUTH_UUID = "31ba0009-6085-4726-be45-040c957391b5"
PLEJD_PING_UUID = "31ba000a-6085-4726-be45-040c957391b5"
