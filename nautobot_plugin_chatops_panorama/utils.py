"""Methods for interactions with Panorama."""

from panos.panorama import Panorama
from panos.device import SystemSettings
from django.utils.text import slugify
<<<<<<< HEAD
from nautobot.dcim.models import Site, Platform, Manufacturer, DeviceType, Device, DeviceRole, Interface
=======
from nautobot.dcim.models import Site
>>>>>>> d35ba2279ab10743fb6264146d65562abd7d14fb
from nautobot.extras.models import Status
from nautobot_plugin_chatops_panorama.constant import PLUGIN_CFG


def connect_panorama() -> Panorama:
    """Method to connect to Panorama instance."""
    pano = Panorama(
        hostname=PLUGIN_CFG["panorama_host"],
        api_username=PLUGIN_CFG["panorama_user"],
        api_password=PLUGIN_CFG["panorama_password"],
    )
    return pano


def _get_or_create_site(site):
    active_status = Status.objects.get(name="Active")
    site_obj, created = Site.objects.get_or_create(name=site, slug=slugify(site))
    if site_obj.status != active_status:
        site_obj.status = active_status
        site_obj.save()
    return site_obj

def _get_or_create_platform(platform: str = "PANOS") -> Platform:
    manufacturer_obj = Manufacturer.objects.get(name="Palo Alto Networks")
    return Platform.objects.get_or_create(name=platform, slug=slugify(platform), manufacturer=manufacturer_obj, napalm_driver="panos")[0]

def _get_or_create_device_type(model: str) -> Platform:
    manufacturer_obj = Manufacturer.objects.get(name="Palo Alto Networks")
    return DeviceType.objects.get_or_create(model=model, slug=slugify(model), manufacturer=manufacturer_obj)[0]

def _get_or_create_device(device: str, serial: str, site: Site, device_type: DeviceType) -> Platform:
    manufacturer_obj = Manufacturer.objects.get(name="Palo Alto Networks")
    device_role_obj = DeviceRole.objects.get(name="Firewall")
    active_status_obj = Status.objects.get(name="Active")
    device_platform_obj=_get_or_create_platform()

    return Device.objects.get_or_create(
        name=device,
        device_role=device_role_obj,
        status=active_status_obj,
        site=site,
        platform=device_platform_obj,
        device_type=device_type
    )[0]


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
        connection.add(device)
        device_system_info = device.show_system_info()["system"]
#        system_setting = device.find("", SystemSettings)
        _device_dict[device_system_info["hostname"]] = {
            "hostname": device_system_info["hostname"],
            "serial": device_system_info["serial"],
            "group_name": group_name,
            "ip_address": device_system_info["ip-address"],
            "status": device.is_active(),
            # TODO (hackathon): Grab this via proxy to firewall to grab get_system_info()
            "model": device_system_info["model"],
            "os_version": device_system_info["sw-version"],
        }
    return _device_dict
