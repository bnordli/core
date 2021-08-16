"""Plejd integration."""
from __future__ import annotations

import logging

import voluptuous as vol

from homeassistant.const import (
    ATTR_ID,
    ATTR_NAME,
    CONF_BINARY_SENSORS,
    CONF_LIGHTS,
    CONF_SENSORS,
    CONF_SWITCHES,
)
from homeassistant.core import callback
from homeassistant.exceptions import PlatformNotReady
from homeassistant.helpers import config_validation as cv

from .const import (
    CONF_CRYPTO_KEY,
    CONF_DBUS_ADDRESS,
    CONF_DISCOVERY_TIMEOUT,
    CONF_OFFSET_MINUTES,
    CONF_SCENES,
    DEFAULT_DBUS_PATH,
    DEFAULT_DISCOVERY_TIMEOUT,
    DOMAIN,
    SCENE_SERVICE,
)
from .plejd_service import PlejdService

_LOGGER = logging.getLogger(__name__)

PLATFORMS = ["binary_sensor", "light", "sensor", "switch"]

CONFIG_SCHEMA = vol.Schema(
    {
        DOMAIN: vol.Schema(
            {
                vol.Required(CONF_CRYPTO_KEY): cv.string,
                vol.Optional(
                    CONF_DISCOVERY_TIMEOUT, default=DEFAULT_DISCOVERY_TIMEOUT
                ): cv.positive_int,
                vol.Optional(CONF_DBUS_ADDRESS, default=DEFAULT_DBUS_PATH): cv.string,
                vol.Optional(CONF_OFFSET_MINUTES, default=0): int,
                vol.Optional(CONF_LIGHTS, default={}): {cv.positive_int: cv.string},
                vol.Optional(CONF_SWITCHES, default={}): {cv.positive_int: cv.string},
                vol.Optional(CONF_BINARY_SENSORS, default={}): {
                    cv.positive_int: cv.string
                },
                vol.Optional(CONF_SENSORS, default={}): {cv.positive_int: cv.string},
                vol.Optional(CONF_SCENES, default={}): {cv.positive_int: cv.string},
            }
        )
    },
    extra=vol.ALLOW_EXTRA,
)


async def async_setup(hass, config):
    """Activate the Plejd integration from configuration yaml."""
    if DOMAIN not in config:
        return True

    plejdconfig = config[DOMAIN]

    devices = {}
    scenes = plejdconfig[CONF_SCENES]
    service = PlejdService(hass, plejdconfig, devices, scenes)
    plejdinfo = {
        "config": plejdconfig,
        "devices": devices,
        "service": service,
        "scenes": scenes,
    }
    hass.data[DOMAIN] = plejdinfo
    for platform in PLATFORMS:
        hass.helpers.discovery.load_platform(platform, DOMAIN, {}, config)

    if not await service.connect():
        raise PlatformNotReady
    await service.check_connection()

    @callback
    def handle_scene_service(call):
        """Handle the trigger scene service."""
        id = call.data.get(ATTR_ID)
        if id is not None:
            service.trigger_scene(id)
            return
        name = call.data.get(ATTR_NAME, "")
        for id, scene_name in scenes.items():
            if name.lower() == scene_name.lower():
                service.trigger_scene(id)
                return
        _LOGGER.warning(
            f"Scene triggered with unknown name '{name}'. Known scenes: {scenes.values()}"
        )
        return

    service_schema = vol.Schema(
        {
            vol.Optional(ATTR_ID): cv.positive_int,
            vol.Optional(ATTR_NAME): vol.Any(*scenes.values()),
        }
    )

    hass.services.async_register(
        DOMAIN, SCENE_SERVICE, handle_scene_service, schema=service_schema
    )
    _LOGGER.debug("Plejd platform setup completed")
    hass.async_create_task(service.request_update())
    return True
