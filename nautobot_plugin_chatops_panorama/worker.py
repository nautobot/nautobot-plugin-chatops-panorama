"""Example rq worker to handle /panorama chat commands with 1 subcommand addition."""
import logging
import requests

from django_rq import job
from nautobot.dcim.models import Device
from nautobot.ipam.models import Service
from nautobot_chatops.choices import CommandStatusChoices
from nautobot_chatops.workers import handle_subcommands, subcommand_of

from panos.panorama import DeviceGroup
from panos.firewall import Firewall
from panos.errors import PanDeviceError
from panos.policies import Rulebase, SecurityRule

from nautobot_plugin_chatops_panorama.constant import UNKNOWN_SITE, ALLOWED_OBJECTS, PLUGIN_CFG
from nautobot_plugin_chatops_panorama.utils.nautobot import (
    _get_or_create_site,
    _get_or_create_device_type,
    _get_or_create_device,
    _get_or_create_interfaces,
    _get_or_create_management_ip,
)

from nautobot_plugin_chatops_panorama.utils.panorama import (
    connect_panorama,
    get_devices,
    compare_address_objects,
    compare_service_objects,
)


logger = logging.getLogger("rq.worker")


def prompt_for_panos_device_group(dispatcher, command, connection):
    """Prompt user for panos device group to check for groups from."""
    group_names = [device.name for device in connection.refresh_devices()]
    dispatcher.prompt_from_menu(command, "Select Panorama Device Group", [(grp, grp) for grp in group_names])
    return CommandStatusChoices.STATUS_ERRORED


def prompt_for_object_type(dispatcher, command):
    """Prompt user for type of object to validate."""
    dispatcher.prompt_from_menu(
        command, "Select an allowed object type", [(object_type, object_type) for object_type in ALLOWED_OBJECTS]
    )
    return CommandStatusChoices.STATUS_ERRORED


def prompt_for_nautobot_device(dispatcher, command):
    """Prompt user for firewall device within Nautobot."""
    _devices = Device.objects.all()
    dispatcher.prompt_from_menu(command, "Select a Nautobot Device", [(dev.name, str(dev.id)) for dev in _devices])
    return CommandStatusChoices.STATUS_ERRORED


def prompt_for_device(dispatcher, command, conn):
    """Prompt the user to select a Palo Alto device."""
    _devices = get_devices(connection=conn)
    dispatcher.prompt_from_menu(command, "Select a Device", [(dev, dev) for dev in _devices])
    return CommandStatusChoices.STATUS_ERRORED


def prompt_for_versions(dispatcher, command, conn):
    """Prompt the user to select a version."""
    conn.software.check()
    versions = conn.software.versions
    dispatcher.prompt_from_menu(command, "Select a Version", [(ver, ver) for ver in versions])
    return CommandStatusChoices.STATUS_ERRORED


@job("default")
def panorama(subcommand, **kwargs):
    """Perform panorama and its subcommands."""
    return handle_subcommands("panorama", subcommand, **kwargs)


@subcommand_of("panorama")
def get_version(dispatcher):
    """Obtain software version information for Panorama."""
    pano = connect_panorama()
    dispatcher.send_markdown(f"The version of Panorama is {pano.refresh_system_info().version}.")
    return CommandStatusChoices.STATUS_SUCCEEDED


@subcommand_of("panorama")
def upload_software(dispatcher, device, version, **kwargs):
    """Upload software to specified Palo Alto device."""
    logger.info("DEVICE: %s", device)
    logger.info("VERSION: %s", version)
    pano = connect_panorama()
    if not device:
        return prompt_for_device(dispatcher, "panorama upload-software", pano)

    if not version:
        prompt_for_versions(dispatcher, f"panorama upload-software {device}", pano)
        return CommandStatusChoices.STATUS_FAILED

    devs = get_devices(connection=pano)
    dispatcher.send_markdown(f"Hey {dispatcher.user_mention()}, you've requested to upload {version} to {device}.")
    _firewall = Firewall(serial=devs[device]["serial"])
    pano.add(_firewall)
    dispatcher.send_markdown("Starting download now...")
    try:
        _firewall.software.download(version)
    except PanDeviceError as err:
        dispatcher.send_markdown(f"There was an issue uploading {version} to {device}. {err}")
        return CommandStatusChoices.STATUS_FAILED
    dispatcher.send_markdown(f"As requested, {version} is being uploaded to {device}.")
    return CommandStatusChoices.STATUS_SUCCEEDED


@subcommand_of("panorama")
def install_software(dispatcher, device, version, **kwargs):
    """Install software to specified Palo Alto device."""
    logger.info("DEVICE: %s", device)
    logger.info("VERSION: %s", version)
    pano = connect_panorama()
    if not device:
        return prompt_for_device(dispatcher, "panorama install-software", pano)

    if not version:
        prompt_for_versions(dispatcher, f"panorama install-software {device}", pano)
        return False

    devs = get_devices(connection=pano)
    dispatcher.send_markdown(f"Hey {dispatcher.user_mention()}, you've requested to install {version} to {device}.")
    _firewall = Firewall(serial=devs[device]["serial"])
    pano.add(_firewall)
    try:
        _firewall.software.install(version)
    except PanDeviceError as err:
        dispatcher.send_markdown(f"There was an issue installing {version} on {device}. {err}")
        return CommandStatusChoices.STATUS_FAILED
    dispatcher.send_markdown(f"As requested, {version} has been installed on {device}.")
    return CommandStatusChoices.STATUS_SUCCEEDED


@subcommand_of("panorama")
def sync_firewalls(dispatcher):
    """Sync firewalls into Nautobot."""
    logger.info("Starting synchronization from Panorama.")
    pano = connect_panorama()
    devices = get_devices(connection=pano)
    device_status = []
    for name, data in devices.items():
        if not data["group_name"]:
            data["group_name"] = UNKNOWN_SITE
        # logic to create site via group_name
        site = _get_or_create_site(data["group_name"])
        # logic to create device type based on model
        device_type = _get_or_create_device_type(data["model"])
        # logic to create device
        device = _get_or_create_device(name, data["serial"], site, device_type, data["os_version"])
        # logic to create interfaces
        interfaces = _get_or_create_interfaces(device)
        # logic to assign ip_address to mgmt interface
        mgmt_ip = _get_or_create_management_ip(device, interfaces[0], data["ip_address"])

        # Add info for device creation to be sent to table creation at the end of task
        status = (name, site, device_type, mgmt_ip, ", ".join([intf.name for intf in interfaces]))
        device_status.append(status)
    return dispatcher.send_large_table(("Name", "Site", "Type", "Primary IP", "Interfaces"), device_status)


@subcommand_of("panorama")
def validate_objects(dispatcher, device, object_type, device_group):
    """Validate Address Objects exist for a device."""
    logger.info("Starting synchronization from Panorama.")
    if not device:
        return prompt_for_nautobot_device(dispatcher, "panorama validate-objects")
    if not object_type:
        return prompt_for_object_type(dispatcher, f"panorama validate-objects {device}")

    pano = connect_panorama()
    if not device_group:
        return prompt_for_panos_device_group(dispatcher, f"panorama validate-objects {device} {object_type}", pano)

    pano = pano.add(DeviceGroup(name=device_group))
    device = Device.objects.get(id=device)
    services = Service.objects.filter(device=device)
    if not services:
        return dispatcher.send_markdown(f"No available services to validate against for {device}")

    object_results = []
    names = set()
    for s in services:
        computed_fields = s.get_computed_fields()

        if object_type == "address" or object_type == "all":
            computed_objects = computed_fields.get("address_objects")
            obj_names = set(computed_objects.split(", "))
            current_objs = obj_names.difference(names)
            names.update(current_objs)
            if computed_objects:
                object_results.extend(compare_address_objects(current_objs, pano))

        if object_type == "service" or object_type == "all":
            computed_objects = computed_fields.get("service_objects")
            obj_names = set(computed_objects.split(", "))
            current_objs = obj_names.difference(names)
            names.update(current_objs)
            if computed_objects:
                object_results.extend(compare_service_objects(current_objs, pano))

    return dispatcher.send_large_table(("Name", "Object Type", "Status (Nautobot/Panorama)"), object_results)


@subcommand_of("panorama")
def get_rules(dispatcher, device, **kwargs):
    """Get list of firewall rules by name."""
    logger.info("Pulling list of firewall rules by name.")
    pano = connect_panorama()
    if not device:
        return prompt_for_nautobot_device(dispatcher, "panorama get-rules")
    device = Device.objects.get(id=device)
    api_key = get_api_key_api()
    params = {
        "key": "LUFRPT1CMVFHYzlESUxaUDY0L2dPMFBHenkrNDZWNjg9dVNxWU5YRncxdkFkNVp6dFVCUy9jM0orMkVwSklmUTlLYlhER1BPV3c1K1lFaFlvNU5OTlZlaXQ4RHg1VkZKKw==",
        "cmd": "<show><rule-hit-count><device-group><entry name='Demo'><pre-rulebase><entry name='security'><rules><all/></rules></entry></pre-rulebase></entry></device-group></rule-hit-count></show>",
        "type": "op",
    }
    host = PLUGIN_CFG["panorama_host"].rstrip("/")
    url = f"https://{host}/api/"
    response = requests.get(url, params=params, verify=False)
    if not response.ok:
        dispatcher.send_markdown(f"Error retrieving device rules.")
        return CommandStatusChoices.STATUS_FAILED
    else:
        dispatcher.send_markdown(response.text)
        return CommandStatusChoices.STATUS_SUCCEEDED
