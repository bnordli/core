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
"""The Plejd light platform."""

import binascii
import logging

from homeassistant.components.light import (
    ATTR_BRIGHTNESS,
    COLOR_MODE_BRIGHTNESS,
    COLOR_MODE_ONOFF,
    LightEntity,
)
from homeassistant.const import CONF_LIGHTS, CONF_NAME, STATE_ON
from homeassistant.core import callback
from homeassistant.helpers.restore_state import RestoreEntity

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


class PlejdLight(LightEntity, RestoreEntity):
    """Representation of a Plejd light."""

    def __init__(self, name, identity, service):
        """Initialize the light."""
        self._name = name
        self._id = identity
        self._service = service
        self._brightness = None

    async def async_added_to_hass(self):
        """Read the current state of the light when it is added to Home Assistant."""
        await super().async_added_to_hass()
        old = await self.async_get_last_state()
        if old is not None:
            self._state = old.state == STATE_ON
            if old.attributes.get(ATTR_BRIGHTNESS) is not None:
                self._attr_supported_color_modes = {COLOR_MODE_BRIGHTNESS}
                self._attr_color_mode = COLOR_MODE_BRIGHTNESS
                brightness = int(old.attributes[ATTR_BRIGHTNESS])
                self._brightness = brightness << 8 | brightness
            else:
                self._attr_supported_color_modes = {COLOR_MODE_ONOFF}
                self._attr_color_mode = COLOR_MODE_ONOFF

        else:
            self._state = False

    @property
    def should_poll(self):
        """Plejd lights should never be polled."""
        return False

    @property
    def name(self):
        """Return the name of this light."""
        return self._name

    @property
    def is_on(self):
        """Return whether this light is on."""
        return self._state

    @property
    def assumed_state(self):
        """Plejd light status are pushed to HA."""
        return False

    @property
    def brightness(self):
        """Return the current brightness of this light."""
        if self._brightness:
            return self._brightness >> 8
        else:
            return None

    @property
    def unique_id(self):
        """Return the unique ID of this light."""
        return self._id

    @callback
    def update_state(self, state, brightness=None):
        """Update the state of the light."""
        self._state = state
        self._brightness = brightness
        state = "on" if state else "off"
        if brightness:
            _LOGGER.debug(
                f"{self._name} ({self._id}) turned {state} with brightness {brightness:04x}"
            )
            self._attr_supported_color_modes = {COLOR_MODE_BRIGHTNESS}
            self._attr_color_mode = COLOR_MODE_BRIGHTNESS
        else:
            _LOGGER.debug(f"{self._name} ({self._id}) turned {state}")
            self._attr_supported_color_modes = {COLOR_MODE_ONOFF}
            self._attr_color_mode = COLOR_MODE_ONOFF
        self.async_schedule_update_ha_state()

    async def async_turn_on(self, **kwargs):
        """Turn the light on."""
        brightness = kwargs.get(ATTR_BRIGHTNESS)
        if brightness is None:
            self._brightness = None
            payload = binascii.a2b_hex(f"{self._id:02x}0110009701")
        else:
            # since ha brightness is just one byte we shift it up and or it in to be able to get max val
            self._brightness = brightness << 8 | brightness
            payload = binascii.a2b_hex(
                f"{self._id:02x}0110009801{self._brightness:04x}"
            )

        _LOGGER.debug(
            f"Turning on {self._name} ({self._id}) with brightness {brightness or 0:02x}"
        )
        await self._service._write(payload)

    async def async_turn_off(self, **kwargs):
        """Turn the light off."""
        payload = binascii.a2b_hex(f"{self._id:02x}0110009700")
        _LOGGER.debug(f"Turning off {self._name} ({self._id})")
        await self._service._write(payload)


async def async_setup_platform(hass, config, async_add_entities, discovery_info=None):
    """Set up the Plejd light platform."""
    if discovery_info is None:
        return

    plejdinfo = hass.data[DOMAIN]
    service = plejdinfo["service"]

    for identity, entity_info in plejdinfo["config"].get(CONF_LIGHTS).items():
        i = int(identity)
        _LOGGER.debug(f"Adding light {i} ({entity_info[CONF_NAME]})")
        plejdinfo["devices"][i] = PlejdLight(entity_info[CONF_NAME], i, service)

    async_add_entities(plejdinfo["devices"].values())

    await service.request_update()
    _LOGGER.debug("plejd light setup completed")
