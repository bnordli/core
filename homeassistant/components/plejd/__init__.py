"""Plejd integration."""
from __future__ import annotations

import binascii

import voluptuous as vol

from homeassistant.const import CONF_LIGHTS, CONF_NAME
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

# from homeassistant.core import HomeAssistant


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
                vol.Required(CONF_LIGHTS, default={}): {
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

    plejdinfo = {
        "key": binascii.a2b_hex(config.get(CONF_CRYPTO_KEY).replace("-", "")),
        "devices": {},
        "config": config[DOMAIN],
    }
    hass.data[DOMAIN] = plejdinfo

    service = PlejdService(hass, config[DOMAIN].get(CONF_DBUS_ADDRESS))
    if not await service.connect():
        raise PlatformNotReady
    await service.check_connection()

    plejdinfo["service"] = service
    hass.helpers.discovery.load_platform("light", DOMAIN, {}, config)
    return True
