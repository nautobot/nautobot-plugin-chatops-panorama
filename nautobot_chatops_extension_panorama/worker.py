"""Example rq worker to handle /panorama chat commands with 1 subcommand addition."""
import logging

from django_rq import job
from nautobot_chatops.choices import CommandStatusChoices
from nautobot_chatops.workers import handle_subcommands, subcommand_of
from .utils import connect_panorama, get_hostnames
from panos.firewall import Firewall

logger = logging.getLogger("rq.worker")


def prompt_for_device(dispatcher, command, conn):
    """Prompt the user to select a Palo Alto device."""
    dev_list = conn.refresh_devices(expand_vsys=False, include_device_groups=False)
    dispatcher.prompt_from_menu(command, "Select a Device", get_hostnames(dev_list))
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
    logger.info(f"DEVICE: {device}")
    logger.info(f"VERSION: {version}")
    pano = connect_panorama()
    if not device:
        return prompt_for_device(dispatcher, "panorama upload-software", pano)

    if not version:
        prompt_for_versions(dispatcher, f"panorama upload-software {device}", pano)
        return False

    dispatcher.send_markdown(f"Hey {dispatcher.user_mention()}, you've requested to upload {version} to {device}.")
    _firewall = Firewall(serial=device)
    pano.add(_firewall)
    dispatcher.send_markdown("Starting download now...")
    _result = _firewall.software.download(version)
    if _result:
        dispatcher.send_markdown(f"As requested, {version} is being uploaded to {device}.")
    else:
        dispatcher.send_markdown(f"There was an issue uploading {version} to {device}.")
        return CommandStatusChoices.STATUS_FAILED
    return CommandStatusChoices.STATUS_SUCCEEDED


@subcommand_of("panorama")
def install_software(dispatcher, device, version, **kwargs):
    """Install software to specified Palo Alto device."""
    logger.info(f"DEVICE: {device}")
    logger.info(f"VERSION: {version}")
    pano = connect_panorama()
    if not device:
        return prompt_for_device(dispatcher, "panorama install-software", pano)

    if not version:
        prompt_for_versions(dispatcher, f"panorama install-software {device}", pano)
        return False

    dispatcher.send_markdown(f"Hey {dispatcher.user_mention()}, you've requested to install {version} to {device}.")
    _firewall = Firewall(serial=device)
    pano.add(_firewall)
    _result = _firewall.software.install(version)
    if _result:
        dispatcher.send_markdown(f"As requested, {version} has been installed on {device}.")
    else:
        dispatcher.send_markdown(f"There was an issue installing {version} on {device}.")
        return CommandStatusChoices.STATUS_FAILED
    return CommandStatusChoices.STATUS_SUCCEEDED
