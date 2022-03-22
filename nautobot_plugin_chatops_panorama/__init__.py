"""Plugin declaration for nautobot_plugin_chatops_panorama."""

__version__ = "1.1.0"

from nautobot.extras.plugins import PluginConfig


class NautobotPluginChatopsPanoramaConfig(PluginConfig):
    """Plugin configuration for the nautobot_plugin_chatops_panorama plugin."""

    name = "nautobot_plugin_chatops_panorama"
    verbose_name = "Nautobot Plugin Chatops Panorama"
    version = __version__
    author = "Network to Code, LLC"
    description = "Nautobot Chatops plugin for Panorama."
    base_url = "nautobot-plugin-chatops-panorama"
    required_settings = []
    min_version = "1.0.0"
    max_version = "1.9999"
    default_settings = {}
    caching_config = {}


config = NautobotPluginChatopsPanoramaConfig  # pylint:disable=invalid-name
