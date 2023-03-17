"""Plugin declaration for nautobot_plugin_chatops_panorama."""
# Metadata is inherited from Nautobot. If not including Nautobot in the environment, this should be added
try:
    from importlib import metadata
except ImportError:
    # Python version < 3.8
    import importlib_metadata as metadata

__version__ = metadata.version(__name__)

from nautobot.extras.plugins import PluginConfig


class NautobotPluginChatopsPanoramaConfig(PluginConfig):
    """Plugin configuration for the nautobot_plugin_chatops_panorama plugin."""

    name = "nautobot_plugin_chatops_panorama"
    verbose_name = "Nautobot Plugin Chatops Panorama"
    version = __version__
    author = "Network to Code, LLC"
    description = "Nautobot Chatops plugin for Panorama.."
    required_settings = []
    min_version = "1.4.0"
    max_version = "1.9999"
    default_settings = {}
    caching_config = {}


config = NautobotPluginChatopsPanoramaConfig  # pylint:disable=invalid-name
