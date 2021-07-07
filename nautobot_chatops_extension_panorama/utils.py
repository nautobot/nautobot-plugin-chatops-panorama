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


def get_devices(connection: Panorama) -> dict:
    """Method to obtain the devices connected to Panorama.

    Args:
        connection (Panorama): Connection object to Panorama.

    Returns:
        dict: Dictionary of all devices attached to Panorama.
    """
    dev_list = connection.refresh_devices(expand_vsys=False, include_device_groups=False)
    _device_dict = {}
    for device in dev_list:
        system_setting = device.find("", SystemSettings)
        _device_dict[system_setting.hostname] = {
            "hostname": system_setting.hostname,
            "serial": device.serial,
            "ip_address": system_setting.ip_address,
        }
    return _device_dict
