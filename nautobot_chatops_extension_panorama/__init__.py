"""Plugin declaration for nautobot_chatops_extension_panorama."""

__version__ = "0.1.0"

from nautobot.extras.plugins import PluginConfig


class NautobotChatopsExtensionPanoramaConfig(PluginConfig):
    """Plugin configuration for the nautobot_chatops_extension_panorama plugin."""

    name = "nautobot_chatops_extension_panorama"
    verbose_name = "Nautobot Chatops Extension Panorama"
    version = __version__
    author = "Network to Code, LLC"
    description = "Nautobot Chatops extension for Panorama."
    base_url = "nautobot-chatops-extension-panorama"
    required_settings = []
    min_version = "1.0.0"
    max_version = "1.9999"
    default_settings = {}
    caching_config = {}


config = NautobotChatopsExtensionPanoramaConfig  # pylint:disable=invalid-name
