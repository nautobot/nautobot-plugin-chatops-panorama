"""Methods for interactions with Panorama."""

import logging
from typing import List

from django.core.exceptions import ValidationError
from django.utils.text import slugify
from nautobot.dcim.models import Site, Platform, Manufacturer, DeviceType, Device, DeviceRole, Interface
from nautobot.extras.models import Status
from nautobot.ipam.models import IPAddress
from nautobot_plugin_chatops_panorama.constant import (
    INTERFACES,
    NAPALM_DRIVER,
    PANOS_DEVICE_ROLE,
    PANOS_MANUFACTURER_NAME,
    PANOS_PLATFORM,
)


logger = logging.getLogger("rq.worker")


def _get_or_create_site(site: str) -> Site:
    """Gets existing site object from DB, or creates one if not currently present.

    Args:
        site (str): Name of site.

    Returns:
        Site: Site object.
    """
    active_status = Status.objects.get(name="Active")
    site_obj, created = Site.objects.get_or_create(name=site, slug=slugify(site))
    if created:
        site_obj.status = active_status
        try:
            site_obj.validated_save()
        except ValidationError as err:
            logger.error("Error saving newly created site %s: %s", site, err)
    return site_obj


def _get_or_create_platform(description: str = "", platform: str = PANOS_PLATFORM) -> Platform:
    """Gets existing platform object from DB, or creates one if not currently present.

    Args:
        description (str, optional): Platform description. Defaults to "".
        platform (str, optional): Platform name. Defaults to PANOS_PLATFORM.

    Returns:
        Platform: Platform object.
    """
    manufacturer_obj = Manufacturer.objects.get(name=PANOS_MANUFACTURER_NAME)
    platform_obj, created = Platform.objects.get_or_create(name=platform, slug=slugify(platform))
    if created:
        platform_obj.manufacturer = manufacturer_obj
        platform_obj.napalm_driver = NAPALM_DRIVER
        platform_obj.description = description
        try:
            platform_obj.validated_save()
        except ValidationError as err:
            logger.error("Error saving newly created platform %s: %s", platform, err)

    return platform_obj


def _get_or_create_manufacturer(manufacturer: str = PANOS_MANUFACTURER_NAME) -> Manufacturer:
    """Gets existing manufacturer object from DB, or creates one if not currently present.

    Args:
        manufacturer (str, optional): Name of manufacturer. Defaults to PANOS_MANUFACTURER_NAME.

    Returns:
        Manufacturer: Manufacturer object.
    """
    manufacturer_obj, created = Manufacturer.objects.get_or_create(name=manufacturer, slug=slugify(manufacturer))
    if created:
        try:
            manufacturer_obj.validated_save()
        except ValidationError as err:
            logger.error("Error saving newly created manufacturer %s: %s", manufacturer, err)
    return manufacturer_obj


def _get_or_create_device_type(model: str, manufacturer: str = PANOS_MANUFACTURER_NAME) -> DeviceType:
    """Gets existing device type object from DB, or creates one if not currently present.

    Args:
        model (str): Model name of device type.
        manufacturer (str, optional): Name of manufacturer. Defaults to PANOS_MANUFACTURER_NAME.

    Returns:
        DeviceType: DeviceType object.
    """
    manufacturer_obj = _get_or_create_manufacturer(manufacturer=manufacturer)
    device_type_obj, created = DeviceType.objects.get_or_create(
        model=model, slug=slugify(model), manufacturer=manufacturer_obj
    )
    if created:
        try:
            device_type_obj.validated_save()
        except ValidationError as err:
            logger.error("Error saving newly created device type %s: %s", model, err)
    return device_type_obj


def _get_or_create_device_role(role_name: str = PANOS_DEVICE_ROLE) -> DeviceRole:
    """Gets existing device role object from DB, or creates one if not currently present.

    Args:
        role_name (str, optional): Name of device role. Defaults to PANOS_DEVICE_ROLE.

    Returns:
        DeviceRole: DeviceRole object.
    """
    device_role_obj, created = DeviceRole.objects.get_or_create(name=role_name, slug=slugify(role_name), color="red")
    if created:
        try:
            device_role_obj.validated_save()
        except ValidationError as err:
            logger.error("Error saving newly created device role %s: %s", role_name, err)
    return device_role_obj


def _get_or_create_device(
    device: str, site: str, device_type: DeviceType, serial: str = "", os_description: str = ""
) -> Device:
    """Gets existing device object from DB, or creates one if not currently present.

    Args:
        device (str): Name of device.
        site (str): Name of site.
        device_type (DeviceType): DeviceType object.
        serial (str, optional): Device serial number. Defaults to "".
        os_description (str, optional): Description of OS. Defaults to "".

    Returns:
        Device: Device object.
    """
    device_role_obj = _get_or_create_device_role()
    active_status_obj = Status.objects.get(name="Active")
    site_obj = _get_or_create_site(site)

    device_obj, created = Device.objects.get_or_create(
        name=device, device_role=device_role_obj, status=active_status_obj, site=site_obj, device_type=device_type
    )
    if created:
        device_obj.platform = _get_or_create_platform(description=os_description)
        if serial:
            device_obj.serial = serial
        try:
            device_obj.validated_save()
        except ValidationError as err:
            logger.error("Error saving newly created device %s: %s", device, err)
    # TODO: Figure this out later
    # device_obj.custom_field_data['public_ipv4'] = '3.13.252.97'
    # device_obj.save()

    return device_obj


# TODO: This function needs to dynamically create the interfaces.
def _get_or_create_interfaces(device: Device) -> List[Interface]:
    """Generate standard interfaces for Palo devices.

    Args:
        device (Device): Device object to create interfaces for.

    Returns:
        List[Interface]: List of Interface objects created.
    """
    interfaces = []
    for interface in INTERFACES:
        interface_obj, created = Interface.objects.get_or_create(name=interface, device=device, type="1000base-t (ge)")
        if created:
            try:
                interface_obj.validated_save()
            except ValidationError as err:
                logger.error("Error saving newly created interface %s: %s", interface, err)
        interfaces.append(interface_obj)

    return interfaces


def _get_or_create_management_ip(device: Device, interfaces: List[Interface], ip_address: str) -> IPAddress:
    """Get or create management IP and assign to Management interface on device.

    Args:
        device (Device): Device object to assign IP to.
        interfaces (List[Interface]): List of all interfaces for device.
        ip_address (str): IP address in CIDR notation to create and assign.

    Returns:
        IPAddress: IPAddress object.
    """
    active_status = Status.objects.get(name="Active")
    interface_obj = [interface for interface in interfaces if interface.name.startswith("Management")][0]
    mgmt_ip_obj, created = IPAddress.objects.get_or_create(
        address=ip_address, status=active_status, assigned_object_id=interface_obj.id
    )

    mgmt_ip_obj.assigned_object_id = interface_obj.id
    mgmt_ip_obj.assigned_object_type_id = 37

    try:
        mgmt_ip_obj.validated_save()
    except ValidationError as err:
        if created:
            logger.error("Error saving newly created management IP %s: %s", ip_address, err)
        else:
            logger.error("Error saving info for management IP %s: %s", ip_address, err)

    device.primary_ip4_id = mgmt_ip_obj.id

    try:
        device.validated_save()
    except ValidationError as err:
        logger.error("Error saving management IP %s to device %s: %s", ip_address, device.name, err)

    return mgmt_ip_obj
