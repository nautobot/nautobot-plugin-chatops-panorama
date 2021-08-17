"""Methods for interactions with Panorama."""

from django.core.exceptions import ValidationError
from django.utils.text import slugify
from nautobot.dcim.models import Site, Platform, Manufacturer, DeviceType, Device, DeviceRole, Interface
from nautobot.extras.models import Status
from nautobot.ipam.models import IPAddress
from nautobot_plugin_chatops_panorama.constant import INTERFACES, PANOS_DEVICE_ROLE, PANOS_MANUFACTURER_NAME, NAPALM_DRIVER, PANOS_PLATFORM

from typing import TYPE_CHECKING

# TODO: Fix
if TYPE_CHECKING or True:
    from typing import Any, Dict, List, Union

def _get_or_create_site(site):
    active_status = Status.objects.get(name="Active")
    site_obj, created = Site.objects.get_or_create(name=site, slug=slugify(site))
    if site_obj.status != active_status:
        site_obj.status = active_status
        site_obj.save()
    elif created:
        try:
            site_obj.validated_save()
        except ValidationError:
            # TODO: Log error here
            pass
    return site_obj


def _get_or_create_platform(description: str, platform: str = PANOS_PLATFORM) -> Platform:
    manufacturer_obj = Manufacturer.objects.get(name=PANOS_MANUFACTURER_NAME)
    platform_obj, created = Platform.objects.get_or_create(
        name=platform,
        slug=slugify(platform),
        manufacturer=manufacturer_obj,
        napalm_driver=NAPALM_DRIVER,
        description=description,
    )
    if platform_obj.description != description:
        platform_obj.description = description
        platform_obj.save()
    elif created:
        try:
            platform_obj.validated_save()
        except ValidationError:
            # TODO: Log error here
            pass

    return platform_obj


def _get_or_create_manufacturer(manufacturer_name: str = PANOS_MANUFACTURER_NAME) -> Manufacturer:
    manufacturer_obj, created = Manufacturer.objects.get_or_create(name=manufacturer_name, slug=slugify(manufacturer_name))
    if created:
        try:
            manufacturer_obj.validated_save()
        except ValidationError:
            # TODO: Log error here
            pass
    return manufacturer_obj


def _get_or_create_device_type(model: str) -> Platform:
    manufacturer_obj = _get_or_create_manufacturer()
    device_type_obj, created = DeviceType.objects.get_or_create(model=model, slug=slugify(model), manufacturer=manufacturer_obj)
    if created:
        try:
            device_type_obj.validated_save()
        except ValidationError:
            # TODO: Log error here
            pass
    return device_type_obj


def _get_or_create_device_role(role_name: str = PANOS_DEVICE_ROLE) -> Platform:
    device_role_obj, created = DeviceRole.objects.get_or_create(name=role_name, slug=slugify(role_name), color="red")
    if created:
        try:
            device_role_obj.validated_save()
        except ValidationError:
            # TODO: Log error here
            pass
    return device_role_obj


def _get_or_create_device(device: str, serial: str, site: str, device_type: DeviceType, os: str) -> Platform:
    device_role_obj = _get_or_create_device_role()
    active_status_obj = Status.objects.get(name="Active")
    device_platform_obj = _get_or_create_platform(description=os)
    site_obj = _get_or_create_site(site)

    device_obj, created = Device.objects.get_or_create(
        name=device,
        device_role=device_role_obj,
        status=active_status_obj,
        site=site_obj,
        platform=device_platform_obj,
        device_type=device_type,
        serial=serial
    )
    if created:
        try:
            device_obj.validated_save()
        except ValidationError:
            # TODO: Log error here
            pass
    # TODO: Work on this
    # device_obj.custom_field_data['public_ipv4'] = '3.13.252.97'
    # device_obj.save()

    return device_obj


def _get_or_create_interfaces(device: Device) -> List[Interface]:
    """Generate standard interfaces for Palo devices."""
    interfaces = []
    for interface in INTERFACES:
        interface_obj, created = Interface.objects.get_or_create(name=interface, device=device, type="1000base-t (ge)")
        if created:
            try:
                interface_obj.validated_save()
            except ValidationError:
                # TODO: Log error here
                pass
        interfaces.append(interface_obj)

    return interfaces


def _get_or_create_management_ip(device: Device, interfaces: List[Interface], ip_address: str):
    """Get or create management IP for an interface on a device."""
    active_status = Status.objects.get(name="Active")
    interface_obj = [interface for interface in interfaces if interface.name.startswith("Management")][0]
    mgmt_ip_obj, created = IPAddress.objects.get_or_create(
        address=ip_address, status=active_status, assigned_object_id=interface_obj.id
    )
    if created:
        try:
            mgmt_ip_obj.validated_save()
        except ValidationError:
            # TODO: Log e
            pass

    mgmt_ip_obj.assigned_object_id = interface_obj.id
    mgmt_ip_obj.assigned_object_type_id = 37
    try:
        mgmt_ip_obj.validated_save()
    except ValidationError:
        # TODO: Log e
        pass

    device.primary_ip4_id = mgmt_ip_obj.id
    try:
        device.validated_save()
    except ValidationError:
        # TODO: Log e
        pass

    return mgmt_ip_obj
