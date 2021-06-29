"""Methods for interactions with Panorama."""

from panos.panorama import Panorama
from panos.device import SystemSettings
from nautobot_chatops_extension_panorama.constant import PLUGIN_CFG


def connect_panorama() -> Panorama:
    try:
        pano = Panorama(
            hostname=PLUGIN_CFG["panorama_host"],
            api_username=PLUGIN_CFG["panorama_user"],
            api_password=PLUGIN_CFG["panorama_password"],
        )
        return pano
    except Exception as err:
        print(f"Unable to connect to {PLUGIN_CFG['panorama_host']} {err}")


def get_hostnames(dev_list: list) -> list:
    """Method to obtain the hostnames of devices in Panorama."""
    _hostnames = []
    for device in dev_list:
        system_setting = device.find("", SystemSettings)
        _hostnames.append((f"{system_setting.hostname}", f"{device.serial}"))
    return _hostnames
