"""Plejd integration."""
from __future__ import annotations

from .const import DOMAIN

# from homeassistant.core import HomeAssistant


PLATFORMS = ["light"]


async def async_setup(hass, config):
    """Activate the Plejd integration from configuration yaml."""
    # Data that you want to share with your platforms
    hass.data[DOMAIN] = {"temperature": 23}

    hass.helpers.discovery.load_platform("sensor", DOMAIN, {}, config)

    return True
