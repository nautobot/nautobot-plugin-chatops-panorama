"""Methods for interactions with Panorama."""

from panos.panorama import Panorama
from panos.device import SystemSettings
import pynautobot
from nautobot_plugin_chatops_panorama.constant import PLUGIN_CFG


def connect_panorama() -> Panorama:
    """Method to connect to Panorama instance."""
    pano = Panorama(
        hostname=PLUGIN_CFG["panorama_host"],
        api_username=PLUGIN_CFG["panorama_user"],
        api_password=PLUGIN_CFG["panorama_password"],
    )
    return pano


def connect_pynautobot() -> pynautobot.api:
    """Provide pynautobot API object.

    Returns:
        pynetbox.api: Nautobot API object.
    """
    return pynautobot.api(PLUGIN_CFG["nautobot_url"], PLUGIN_CFG["nautobot_token"])


def _get_or_create_site(nb, site):
    site = nb.dcim.site.get(name=site)
    if not site:
        nb.dcim.site.create(name=site)


def _get_group(groups, serial):
    """Sort through fetched groups and serials and return group.

    Args:
        groups (dict): Group names as keys and serial numbers in a list
        serial (str): Serial to search for within group serial number lists

    Returns:
        group_name (str): Name of group serial is part of or None if serial not in a group
    """
    for k, v in groups.items():
        if serial in v:
            return k


def get_devices(connection: Panorama) -> dict:
    """Method to obtain the devices connected to Panorama.

    Args:
        connection (Panorama): Connection object to Panorama.

    Returns:
        dict: Dictionary of all devices attached to Panorama.
    """
    dev_list = connection.refresh_devices(expand_vsys=False, include_device_groups=False)

    group_names = [device.name for device in connection.refresh_devices()]
    group_xml_obj = connection.op("show devicegroups")
    groups_and_devices = {}
    for group in group_names:
        if group not in groups_and_devices:
            groups_and_devices[group] = []
        groups_and_devices[group].extend(
            [x.text for x in group_xml_obj.find(f".//entry[@name='{group}']").findall(".//serial")]
        )

    _device_dict = {}
    for device in dev_list:
        group_name = _get_group(groups_and_devices, device.serial)

        system_setting = device.find("", SystemSettings)
        _device_dict[system_setting.hostname] = {
            "hostname": system_setting.hostname,
            "serial": device.serial,
            "group_name": group_name,
            "ip_address": system_setting.ip_address,
            "status": device.is_active(),
            # TODO (hackathon): Grab this via proxy to firewall to grab get_system_info()
            "model": "PA-VM",
        }
    return _device_dict
