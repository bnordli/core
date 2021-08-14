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
"""The Plejd switch platform."""

import binascii
import logging

from homeassistant.components.switch import SwitchEntity
from homeassistant.const import CONF_DEVICES, CONF_SWITCHES, STATE_ON
from homeassistant.core import callback
from homeassistant.helpers.restore_state import RestoreEntity

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


class PlejdSwitch(SwitchEntity, RestoreEntity):
    """Representation of a Plejd switch."""

    def __init__(self, name, identity, service):
        """Initialize the switch."""
        self._name = name
        self._id = identity
        self._service = service
        self._brightness = None

    async def async_added_to_hass(self):
        """Read the current state of the switch when it is added to Home Assistant."""
        await super().async_added_to_hass()
        old = await self.async_get_last_state()
        if old is not None:
            self._state = old.state == STATE_ON
        else:
            self._state = False

    @property
    def should_poll(self):
        """Plejd switches should never be polled."""
        return False

    @property
    def name(self):
        """Return the name of this switch."""
        return self._name

    @property
    def is_on(self):
        """Return whether this switch is on."""
        return self._state

    @property
    def assumed_state(self):
        """Plejd switch status are pushed to HA."""
        return False

    @property
    def unique_id(self):
        """Return the unique ID of this switch."""
        return self._id

    @callback
    def update_state(self, state, brightness=None):
        """Update the state of the switch."""
        self._state = state
        state = "on" if state else "off"
        _LOGGER.debug(f"{self._name} ({self._id}) turned {state}")
        self.async_schedule_update_ha_state()

    async def async_turn_on(self, **kwargs):
        """Turn the switch on."""
        payload = binascii.a2b_hex(f"{self._id:02x}0110009701")
        _LOGGER.debug(f"Turning on {self._name} ({self._id})")
        await self._service._write(payload)

    async def async_turn_off(self, **kwargs):
        """Turn the switch off."""
        payload = binascii.a2b_hex(f"{self._id:02x}0110009700")
        _LOGGER.debug(f"Turning off {self._name} ({self._id})")
        await self._service._write(payload)


def setup_platform(hass, config, add_entities, discovery_info=None):
    """Set up the Plejd switch platform."""
    if discovery_info is None:
        return

    plejdinfo = hass.data[DOMAIN]
    service = plejdinfo["service"]
    switches = []

    for device_info in plejdinfo["config"].get(CONF_DEVICES).values():
        for identity, switch_name in device_info[CONF_SWITCHES].items():
            i = int(identity)
            if i in plejdinfo["devices"]:
                _LOGGER.warning(f"Found duplicate definition for Plejd device {i}.")
                continue
            _LOGGER.debug(f"Adding switch {i} ({switch_name})")
            switch = PlejdSwitch(switch_name, i, service)
            plejdinfo["devices"][i] = switch
            switches.append(switch)

    add_entities(switches)


# def make_device(device_id, device_info):
#    """Create device information for device registry."""
#    return {
#        ATTR_IDENTIFIERS: {(DOMAIN, device_id)},
#        ATTR_NAME: device_info[CONF_NAME],
#        ATTR_MANUFACTURER: "Plejd",
#        ATTR_MODEL: device_info[CONF_TYPE],
#    }
