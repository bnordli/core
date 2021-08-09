"""Plejd integration."""
from __future__ import annotations

import logging

import voluptuous as vol

from homeassistant.const import CONF_BINARY_SENSORS, CONF_LIGHTS, CONF_NAME
from homeassistant.exceptions import PlatformNotReady
from homeassistant.helpers import config_validation as cv

from .const import (
    CONF_CRYPTO_KEY,
    CONF_DBUS_ADDRESS,
    CONF_DISCOVERY_TIMEOUT,
    CONF_OFFSET_MINUTES,
    DEFAULT_DBUS_PATH,
    DEFAULT_DISCOVERY_TIMEOUT,
    DOMAIN,
)
from .plejd_service import PlejdService

_LOGGER = logging.getLogger(__name__)

PLATFORMS = ["light"]

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
                vol.Optional(CONF_LIGHTS, default={}): {
                    cv.string: vol.Schema({vol.Required(CONF_NAME): cv.string})
                },
                vol.Optional(CONF_BINARY_SENSORS, default={}): {
                    cv.string: vol.Schema({vol.Required(CONF_NAME): cv.string})
                },
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
    service = PlejdService(hass, plejdconfig, devices)
    plejdinfo = {
        "config": plejdconfig,
        "devices": devices,
        "service": service,
    }
    hass.data[DOMAIN] = plejdinfo
    hass.helpers.discovery.load_platform("light", DOMAIN, {}, config)

    if not await service.connect():
        raise PlatformNotReady
    await service.check_connection()
    _LOGGER.debug("Plejd platform setup completed")
    hass.async_create_task(service.request_update())
    return True
