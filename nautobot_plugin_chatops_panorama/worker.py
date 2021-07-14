"""Example rq worker to handle /panorama chat commands with 1 subcommand addition."""
import logging

from django_rq import job
from nautobot_chatops.choices import CommandStatusChoices
from nautobot_chatops.workers import handle_subcommands, subcommand_of
from panos.firewall import Firewall
from panos.errors import PanDeviceError
from .utils import (
    connect_panorama,
    get_devices,
    _get_or_create_site,
    _get_or_create_device_type,
    _get_or_create_device,
    _get_or_create_interfaces,
    _get_or_create_management_ip,
)
from nautobot_plugin_chatops_panorama.constant import UNKNOWN_SITE, INTERFACES


logger = logging.getLogger("rq.worker")


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
