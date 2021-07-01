"""Methods for interactions with Panorama."""

from panos.panorama import Panorama
from panos.device import SystemSettings
from nautobot_chatops_extension_panorama.constant import PLUGIN_CFG


def connect_panorama() -> Panorama:
    """Method to connect to Panorama instance."""
    pano = Panorama(
        hostname=PLUGIN_CFG["panorama_host"],
        api_username=PLUGIN_CFG["panorama_user"],
        api_password=PLUGIN_CFG["panorama_password"],
    )
    return pano


def get_hostnames(dev_list: list) -> list:
    """Method to obtain the hostnames of devices in Panorama."""
    _hostnames = []
    for device in dev_list:
        system_setting = device.find("", SystemSettings)
        _hostnames.append(system_setting.hostname, device.serial)
    return _hostnames
