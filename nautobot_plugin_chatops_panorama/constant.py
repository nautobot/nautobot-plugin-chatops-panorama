"""Storage of data that will not change throughout the life cycle of application."""
from django.conf import settings

PLUGIN_CFG = settings.PLUGINS_CONFIG["nautobot_plugin_chatops_panorama"]
INTERFACES = [
    "Management",
    "ethernet0/0",
    "ethernet0/1",
    "ethernet0/2",
    "ethernet0/3",
    "ethernet0/4",
    "ethernet0/5",
    "ethernet0/6",
    "ethernet0/7",
]

UNKNOWN_SITE = "Unknown"

ALLOWED_OBJECTS = ("full", "address", "service")
