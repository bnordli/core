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
from homeassistant.const import CONF_LIGHTS, STATE_ON
from homeassistant.core import callback
from homeassistant.helpers.restore_state import RestoreEntity

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


class PlejdLight(LightEntity, RestoreEntity):
    """Representation of a Plejd light."""

    _attr_should_poll = False
    _attr_assumed_state = False

    def __init__(self, name, identity, service):
        """Initialize the light."""
        self._attr_name = name
        self._attr_unique_id = identity
        self._service = service
        self._brightness = None

    async def async_added_to_hass(self):
        """Read the current state of the light when it is added to Home Assistant."""
        await super().async_added_to_hass()
        old = await self.async_get_last_state()
        if old is not None:
            self._attr_is_on = old.state == STATE_ON
            if old.attributes.get(ATTR_BRIGHTNESS) is not None:
                self._attr_supported_color_modes = {COLOR_MODE_BRIGHTNESS}
                self._attr_color_mode = COLOR_MODE_BRIGHTNESS
                brightness = int(old.attributes[ATTR_BRIGHTNESS])
                self._brightness = brightness << 8 | brightness
            else:
                self._attr_supported_color_modes = {COLOR_MODE_ONOFF}
                self._attr_color_mode = COLOR_MODE_ONOFF
        else:
            self._attr_is_on = False

    @property
    def brightness(self):
        """Return the current brightness of this light."""
        if self._brightness:
            return self._brightness >> 8
        else:
            return None

    @callback
    def update_state(self, state, brightness=None):
        """Update the state of the light."""
        self._attr_is_on = state
        self._brightness = brightness
        if brightness:
            _LOGGER.debug(
                f"{self.name} ({self.unique_id}) turned {self.state} with brightness {brightness:04x}"
            )
            self._attr_supported_color_modes = {COLOR_MODE_BRIGHTNESS}
            self._attr_color_mode = COLOR_MODE_BRIGHTNESS
        else:
            _LOGGER.debug(f"{self.name} ({self.unique_id}) turned {self.state}")
            self._attr_supported_color_modes = {COLOR_MODE_ONOFF}
            self._attr_color_mode = COLOR_MODE_ONOFF
        self.async_schedule_update_ha_state()

    async def async_turn_on(self, **kwargs):
        """Turn the light on."""
        brightness = kwargs.get(ATTR_BRIGHTNESS)
        if brightness is None:
            self._brightness = None
            payload = binascii.a2b_hex(f"{self.unique_id:02x}0110009701")
        else:
            # since ha brightness is just one byte we shift it up and or it in to be able to get max val
            self._brightness = brightness << 8 | brightness
            payload = binascii.a2b_hex(
                f"{self.unique_id:02x}0110009801{self._brightness:04x}"
            )

        _LOGGER.debug(
            f"Turning on {self.name} ({self.unique_id}) with brightness {brightness or 0:02x}"
        )
        await self._service._write(payload)

    async def async_turn_off(self, **kwargs):
        """Turn the light off."""
        payload = binascii.a2b_hex(f"{self.unique_id:02x}0110009700")
        _LOGGER.debug(f"Turning off {self.name} ({self.unique_id})")
        await self._service._write(payload)


def setup_platform(hass, config, add_entities, discovery_info=None):
    """Set up the Plejd light platform."""
    if discovery_info is None:
        return

    plejdinfo = hass.data[DOMAIN]
    service = plejdinfo["service"]
    lights = []

    for identity, light_name in plejdinfo["config"][CONF_LIGHTS].items():
        i = int(identity)
        if i in plejdinfo["devices"]:
            _LOGGER.warning(f"Found duplicate definition for Plejd device {i}.")
            continue
        _LOGGER.debug(f"Adding light {i} ({light_name})")
        light = PlejdLight(light_name, i, service)
        plejdinfo["devices"][i] = light
        lights.append(light)

    add_entities(lights)


# def make_device(device_id, device_info):
#    """Create device information for device registry."""
#    return {
#        ATTR_IDENTIFIERS: {(DOMAIN, device_id)},
#        ATTR_NAME: device_info[CONF_NAME],
#        ATTR_MANUFACTURER: "Plejd",
#        ATTR_MODEL: device_info[CONF_TYPE],
#    }
