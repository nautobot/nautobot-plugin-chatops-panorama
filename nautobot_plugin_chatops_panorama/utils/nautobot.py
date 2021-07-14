"""Methods for interactions with Panorama."""
from typing import List

from django.utils.text import slugify
from nautobot.dcim.models import Site, Platform, Manufacturer, DeviceType, Device, DeviceRole, Interface
from nautobot.extras.models import Status
from nautobot.ipam.models import IPAddress
from nautobot_plugin_chatops_panorama.constant import PLUGIN_CFG


def _get_or_create_site(site):
    active_status = Status.objects.get(name="Active")
    site_obj, created = Site.objects.get_or_create(name=site, slug=slugify(site))
    if site_obj.status != active_status:
        site_obj.status = active_status
        site_obj.save()
    return site_obj


def _get_or_create_platform(description: str, platform: str = "PANOS") -> Platform:
    manufacturer_obj = Manufacturer.objects.get(name="Palo Alto Networks")
    platform = Platform.objects.get_or_create(
        name=platform,
        slug=slugify(platform),
        manufacturer=manufacturer_obj,
        napalm_driver="panos",
        description=description,
    )[0]
    if platform.description != description:
        platform.description = description
        platform.save()

    return platform


def _get_or_create_device_type(model: str) -> Platform:
    manufacturer_obj = Manufacturer.objects.get(name="Palo Alto Networks")
    return DeviceType.objects.get_or_create(model=model, slug=slugify(model), manufacturer=manufacturer_obj)[0]


def _get_or_create_device(device: str, serial: str, site: Site, device_type: DeviceType, os: str) -> Platform:
    manufacturer_obj = Manufacturer.objects.get(name="Palo Alto Networks")
    device_role_obj = DeviceRole.objects.get(name="Firewall")
    active_status_obj = Status.objects.get(name="Active")
    device_platform_obj = _get_or_create_platform(description=os)

    return Device.objects.get_or_create(
        name=device,
        device_role=device_role_obj,
        status=active_status_obj,
        site=site,
        platform=device_platform_obj,
        device_type=device_type,
    )[0]


def _get_or_create_interfaces(device: Device) -> List[Interface]:
    """Generate standard interfaces for Palo devices."""
    interfaces = []
    for intf in constant.INTERFACES:
        interfaces.append(Interface.objects.get_or_create(name=intf, device=device, type="1000base-t (ge)")[0])

    return interfaces


def _get_or_create_management_ip(device: Device, interface: Interface, ip_address: str):
    active_status = Status.objects.get(name="Active")
    mgmt_ip = IPAddress.objects.get_or_create(
        address=ip_address, status=active_status, assigned_object_id=interface.id
    )[0]
    device.primary_ip4 = mgmt_ip
    device.save()

    return mgmt_ip




