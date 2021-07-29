# Copyright 2019 Klas Lindfors <klali@avm.se>

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""The Plejd service code."""

import asyncio
import binascii
from datetime import datetime, timedelta
import logging
import os
import re
import struct

from homeassistant.const import EVENT_HOMEASSISTANT_STOP
from homeassistant.core import callback
from homeassistant.helpers.event import async_track_point_in_utc_time
import homeassistant.util.dt as dt_util

from .const import (
    BLUEZ_ADAPTER_IFACE,
    BLUEZ_DEVICE_IFACE,
    BLUEZ_SERVICE_NAME,
    DBUS_OM_IFACE,
    DBUS_PROP_IFACE,
    DOMAIN,
    GATT_CHRC_IFACE,
    GATT_SERVICE_IFACE,
    PLEJD_AUTH_UUID,
    PLEJD_DATA_UUID,
    PLEJD_LAST_DATA_UUID,
    PLEJD_LIGHTLEVEL_UUID,
    PLEJD_PING_UUID,
    PLEJD_SVC_UUID,
    TIME_DELTA_SYNC,
)

_LOGGER = logging.getLogger(__name__)


class PlejdBus:
    """Representation of the message bus connected to Plejd."""

    def __init__(self, address):
        """Initialize the bus."""
        self._address = address
        self._chars = {}

    async def write_data(self, char, data):
        """Write data to one characteristic."""
        await self._chars[char].call_write_value(data, {})

    async def read_data(self, char):
        """Read data from one characteristic."""
        return await self._chars[char].call_read_value({})

    async def add_callback(self, method, callback):
        """Register a callback on a characteristic."""

        @callback
        def cb(iface, changed_props, invalidated_props):
            if iface != GATT_CHRC_IFACE:
                return
            if not len(changed_props):
                return
            value = changed_props.get("Value", None)
            if not value:
                return
            callback(value.value)

        self._chars[method + "_prop"].on_properties_changed(cb)
        await self._chars[method].call_start_notify()

    async def _get_interface(self, path, interface):
        introspection = await self._bus.introspect(BLUEZ_SERVICE_NAME, path)
        object = self._bus.get_proxy_object(BLUEZ_SERVICE_NAME, path, introspection)
        return object.get_interface(interface)

    async def connect(self):
        """Connect to the message bus."""
        from dbus_next import BusType
        from dbus_next.aio import MessageBus

        messageBus = MessageBus(bus_type=BusType.SYSTEM, bus_address=self._address)
        self._bus = await messageBus.connect()
        self._om = await self._get_interface("/", DBUS_OM_IFACE)
        self._adapter = await self._get_adapter()
        if not self._adapter:
            _LOGGER.error("No bluetooth adapter discovered")
            return False
        return True

    async def _get_adapter(self):
        om_objects = await self._om.call_get_managed_objects()
        for path, interfaces in om_objects.items():
            if BLUEZ_ADAPTER_IFACE in interfaces.keys():
                _LOGGER.debug(f"Discovered bluetooth adapter {path}")
                return await self._get_interface(path, BLUEZ_ADAPTER_IFACE)

    async def disconnect_devices(self):
        """Disconnect all currently connected devices."""
        om_objects = await self._om.call_get_managed_objects()
        for path, interfaces in om_objects.items():
            if BLUEZ_DEVICE_IFACE in interfaces.keys():
                dev = await self._get_interface(path, BLUEZ_DEVICE_IFACE)
                connected = await dev.get_connected()
                if connected:
                    _LOGGER.debug(f"Disconnecting {path}")
                    await dev.call_disconnect()
                    _LOGGER.debug(f"Disconnected {path}")
                await self._adapter.call_remove_device(path)

    async def connect_device(self, timeout):
        """Get all plejds and connect to the closest device."""
        from dbus_next import Variant
        from dbus_next.errors import DBusError

        plejds = []

        @callback
        def on_interfaces_added(path, interfaces):
            if (
                BLUEZ_DEVICE_IFACE in interfaces
                and PLEJD_SVC_UUID in interfaces[BLUEZ_DEVICE_IFACE]["UUIDs"].value
            ):
                plejds.append({"path": path})

        self._om.on_interfaces_added(on_interfaces_added)

        scan_filter = {
            "UUIDs": Variant("as", [PLEJD_SVC_UUID]),
            "Transport": Variant("s", "le"),
        }
        await self._adapter.call_set_discovery_filter(scan_filter)
        await self._adapter.call_start_discovery()
        await asyncio.sleep(timeout)

        if len(plejds) == 0:
            _LOGGER.warning("No plejd devices found")
            return False

        _LOGGER.debug(f"Found {len(plejds)} plejd devices")
        for plejd in plejds:
            dev = await self._get_interface(plejd["path"], BLUEZ_DEVICE_IFACE)
            plejd["RSSI"] = await dev.get_rssi()
            plejd["obj"] = dev
            _LOGGER.debug(f"Discovered plejd {plejd['path']} with RSSI {plejd['RSSI']}")

        plejds.sort(key=lambda a: a["RSSI"], reverse=True)
        for plejd in plejds:
            try:
                _LOGGER.debug(f"Connecting to {plejd['path']}")
                await plejd["obj"].call_connect()
                _LOGGER.debug(f"Connected to {plejd['path']}")
                break
            except DBusError as e:
                _LOGGER.warning(f"Error connecting to plejd: {e}")
        await self._adapter.call_stop_discovery()
        await asyncio.sleep(timeout)
        return True

    async def get_plejd_address(self):
        """Get the plejd address and also collect characteristics."""
        om_objects = await self._om.call_get_managed_objects()
        chrcs = []

        for path, interfaces in om_objects.items():
            if GATT_CHRC_IFACE in interfaces.keys():
                chrcs.append(path)

        for path, interfaces in om_objects.items():
            if GATT_SERVICE_IFACE not in interfaces.keys():
                continue

            service = await self._get_interface(path, GATT_SERVICE_IFACE)
            uuid = await service.get_uuid()
            if uuid != PLEJD_SVC_UUID:
                continue

            dev = await service.get_device()
            x = re.search("dev_([0-9A-F_]+)$", dev)
            addr = binascii.a2b_hex(x.group(1).replace("_", ""))[::-1]

            # Process the characteristics.
            chrc_paths = [d for d in chrcs if d.startswith(path + "/")]
            for chrc_path in chrc_paths:
                chrc = await self._get_interface(chrc_path, GATT_CHRC_IFACE)
                chrc_prop = await self._get_interface(chrc_path, DBUS_PROP_IFACE)

                uuid = await chrc.get_uuid()

                if uuid == PLEJD_DATA_UUID:
                    self._chars["data"] = chrc
                elif uuid == PLEJD_LAST_DATA_UUID:
                    self._chars["last_data"] = chrc
                    self._chars["last_data_prop"] = chrc_prop
                elif uuid == PLEJD_AUTH_UUID:
                    self._chars["auth"] = chrc
                elif uuid == PLEJD_PING_UUID:
                    self._chars["ping"] = chrc
                elif uuid == PLEJD_LIGHTLEVEL_UUID:
                    self._chars["lightlevel"] = chrc
                    self._chars["lightlevel_prop"] = chrc_prop

            return addr

        return None


class PlejdService:
    """Representation of the Plejd service."""

    def __init__(self, hass, address):
        """Initialize the service."""
        self._hass = hass
        self._pi = hass.data[DOMAIN]
        self._address = address
        self._bus = None
        self._remove_timer = lambda: ()
        hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, self._stop_plejd)

    async def connect(self):
        """Connect to the Plejd service."""
        pi = self._pi
        self._bus = PlejdBus(self._address)
        if not await self._bus.connect():
            return False
        await self._bus.disconnect_devices()
        if not await self._bus.connect_device(pi["discovery_timeout"]):
            return False

        pi["address"] = await self._bus.get_plejd_address()
        if not pi["address"]:
            _LOGGER.warning("Failed connecting to plejd service")
            return False
        if not await self._authenticate(pi["key"]):
            return False

        @callback
        def handle_notification_cb(value):
            dec = _plejd_enc_dec(pi["key"], pi["address"], value)
            _LOGGER.debug(f"Received command {binascii.b2a_hex(dec)}")

            # Format
            # 012345...
            # irrccdddd
            # i = device_id
            #     0 = broadcast
            #     1 = broadcast time
            #     2 = scenes
            #     3... id
            # r = read?
            # c = command
            #     001b: time
            #     0016: button push, data = button + unknown
            #     0021: set scene, data = scene id
            #     0097: state update, data = state, dim
            #     00c8, 0098: state/dim update
            # d = data

            # check if this is a device we care about
            if dec[0] in pi["devices"]:
                device = pi["devices"][dec[0]]
            elif dec[0] == 0x01 and dec[3:5] == b"\x00\x1b":
                n = dt_util.now().replace(tzinfo=None)
                time = datetime.fromtimestamp(struct.unpack_from("<I", dec, 5)[0])
                n = n + timedelta(minutes=pi["offset_minutes"])
                delta = abs(time - n)
                _LOGGER.debug(f"Plejd network reports time as '{time}'")
                s = delta.total_seconds()
                if s > TIME_DELTA_SYNC:
                    _LOGGER.info(
                        f"Plejd time delta is {s} seconds, setting time to '{n}'."
                    )
                    ntime = b"\x00\x01\x10\x00\x1b"
                    ntime += struct.pack("<I", int(n.timestamp())) + b"\x00"
                    self._hass.async_create_task(self._write(ntime))
                return
            else:
                _LOGGER.debug(
                    f"No match for device '{dec[0]:02x}' ({binascii.b2a_hex(dec)})"
                )
                return
            dim = None
            state = None
            if dec[3:5] == b"\x00\xc8" or dec[3:5] == b"\x00\x98":
                # 00c8 and 0098 both mean state+dim
                state = dec[5]
                dim = int.from_bytes(dec[6:8], "little")
            elif dec[3:5] == b"\x00\x97":
                # 0097 is state only
                state = dec[5]
            else:
                _LOGGER.debug(
                    "No match for command '%s' (%s)"
                    % (binascii.b2a_hex(dec[3:5]), binascii.b2a_hex(dec))
                )
                return

            device.update_state(bool(state), dim)

        @callback
        def handle_lightlevel_cb(value):
            # One or two messages of format
            # 0123456789
            # is???dd???
            # i = device_id
            # s = state (0 or 1)
            # d = brightness
            if len(value) != 20 and len(value) != 10:
                lightlevel = binascii.b2a_hex(value)
                _LOGGER.debug(
                    f"Unknown length data received for lightlevel: '{lightlevel}'"
                )
                return

            msgs = [value[0:10]]
            if len(value) == 20:
                msgs.append(value[10:20])

            for m in msgs:
                if m[0] not in pi["devices"]:
                    continue
                device = pi["devices"][m[0]]
                device.update_state(bool(m[1]), int.from_bytes(m[5:7], "little"))

        await self._bus.add_callback("last_data", handle_notification_cb)
        await self._bus.add_callback("lightlevel", handle_lightlevel_cb)

        return True

    async def ping(self, now):
        """Send a ping and then schedule another in the future."""
        if not await self._send_ping():
            await self.connect()
        self._remove_timer = async_track_point_in_utc_time(
            self._hass, self.ping, dt_util.utcnow() + timedelta(seconds=300)
        )

    async def _stop_plejd(self, event):
        self._remove_timer()

    async def _authenticate(self, key):
        from dbus_next.errors import DBusError

        try:
            await self._bus.write_data("auth", b"\x00")
            challenge = await self._bus.read_data("auth")
            await self._bus.write_data("auth", _plejd_chalresp(key, challenge))
        except DBusError as e:
            _LOGGER.warning(f"Plejd authentication errored: {e}")
            return False
        return True

    async def _send_ping(self):
        from dbus_next.errors import DBusError

        ping = os.urandom(1)
        try:
            await self._bus.write_data("ping", ping)
            pong = await self._bus.read_data("ping")
        except DBusError as e:
            _LOGGER.warning(f"Plejd ping errored: {e}")
            return False
        if (ping[0] + 1) & 0xFF != pong[0]:
            _LOGGER.warning(f"Plejd ping failed {ping[0]:02x} - {pong[0]:02x}")
            return False

        _LOGGER.debug(f"Successfully pinged with {ping[0]:02x}")
        return True

    async def _write(self, payload):
        from dbus_next.errors import DBusError

        pi = self._pi
        if not self._bus:
            _LOGGER.warning("Tried to write to plejd when not connected")
            return

        try:
            data = _plejd_enc_dec(pi["key"], pi["address"], payload)
            await self._bus.write_data("data", data)
        except DBusError as e:
            _LOGGER.warning(f"Write failed, reconnecting: '{e}'")
            await self.connect()
            data = _plejd_enc_dec(pi["key"], pi["address"], payload)
            await self._bus.write_data("data", data)

    async def request_update(self):
        """Request an update of all devices."""
        await self._bus.write_data("lightlevel", b"\x01")


def _plejd_chalresp(key, chal):
    import hashlib

    k = int.from_bytes(key, "big")
    c = int.from_bytes(chal, "big")

    intermediate = hashlib.sha256((k ^ c).to_bytes(16, "big")).digest()
    part1 = int.from_bytes(intermediate[:16], "big")
    part2 = int.from_bytes(intermediate[16:], "big")
    resp = (part1 ^ part2).to_bytes(16, "big")
    return resp


def _plejd_enc_dec(key, addr, data):
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    buf = bytearray(addr * 2)
    buf += addr[:4]

    ct = (
        Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        .encryptor()
        .update(buf)
    )

    output = b""
    for i in range(len(data)):
        output += struct.pack("B", data[i] ^ ct[i % 16])

    return output
