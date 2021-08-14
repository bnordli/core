# Copyright 2021 Børge Nordli <bnordli@gmail.com>

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
"""The Plejd binary sensor platform."""

import logging

from homeassistant.components.binary_sensor import BinarySensorEntity
from homeassistant.const import CONF_BINARY_SENSORS, CONF_DEVICES, STATE_ON
from homeassistant.core import callback
from homeassistant.helpers.restore_state import RestoreEntity

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


class PlejdButton(BinarySensorEntity, RestoreEntity):
    """Representation of a Plejd button."""

    def __init__(self, name, identity, service):
        """Initialize the binary sensor."""
        self._name = name
        self._id = identity
        self._service = service

    async def async_added_to_hass(self):
        """Read the current state of the button when it is added to Home Assistant."""
        await super().async_added_to_hass()
        old = await self.async_get_last_state()
        if old is not None:
            self._state = old.state == STATE_ON
        else:
            self._state = False

    @property
    def should_poll(self):
        """Plejd buttons should never be polled."""
        return False

    @property
    def name(self):
        """Return the name of this button."""
        return self._name

    @property
    def is_on(self):
        """Return whether this button is on."""
        return self._state

    @property
    def assumed_state(self):
        """Plejd button status are pushed to HA."""
        return False

    @property
    def unique_id(self):
        """Return the unique ID of this button."""
        return self._id

    @callback
    def update_state(self, state, brightness=None):
        """Update the state of the button."""
        self._state = state
        state = "on" if state else "off"
        _LOGGER.debug(f"{self._name} ({self._id}) turned {state}")
        self.async_schedule_update_ha_state()


def setup_platform(hass, config, add_entities, discovery_info=None):
    """Set up the Plejd binary sensor platform."""
    if discovery_info is None:
        return

    plejdinfo = hass.data[DOMAIN]
    service = plejdinfo["service"]
    buttons = []

    for device_info in plejdinfo["config"].get(CONF_DEVICES).values():
        for identity, sensor_name in device_info[CONF_BINARY_SENSORS].items():
            i = int(identity)
            if i in plejdinfo["devices"]:
                _LOGGER.warning(f"Found duplicate definition for Plejd device {i}.")
                continue
            _LOGGER.debug(f"Adding binary sensor {i} ({sensor_name})")
            button = PlejdButton(sensor_name, i, service)
            plejdinfo["devices"][i] = button
            buttons.append(button)

    add_entities(buttons)
