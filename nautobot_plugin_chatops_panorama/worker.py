"""Example rq worker to handle /panorama chat commands with 1 subcommand addition."""
import logging
import os
import re
from copy import deepcopy
from ipaddress import ip_network
from netutils.protocol_mapper import PROTO_NAME_TO_NUM

from django_rq import job
from nautobot.dcim.models import Device, Interface
from nautobot_chatops.choices import CommandStatusChoices
from nautobot_chatops.workers import handle_subcommands, subcommand_of

from panos.firewall import Firewall
from panos.errors import PanDeviceError

from nautobot_plugin_chatops_panorama.constant import ALLOWED_OBJECTS

from nautobot_plugin_chatops_panorama.utils.panorama import (
    connect_panorama,
    get_devices,
    get_rule_match,
    start_packet_capture,
    get_all_rules,
    split_rules,
)

PALO_LOGO_PATH = "nautobot_palo/palo_transparent.png"
PALO_LOGO_ALT = "Palo Alto Networks Logo"

logger = logging.getLogger("rq.worker")


def palo_logo(dispatcher):
    """Construct an image_element containing the locally hosted Palo Alto Networks logo."""
    return dispatcher.image_element(dispatcher.static_url(PALO_LOGO_PATH), alt_text=PALO_LOGO_ALT)


def prompt_for_panos_device_group(dispatcher, command, connection):
    """Prompt user for panos device group to check for groups from."""
    group_names = [device.name for device in connection.refresh_devices()]
    dispatcher.prompt_from_menu(command, "Select Panorama Device Group", [(grp, grp) for grp in group_names])
    return CommandStatusChoices.STATUS_SUCCEEDED


def prompt_for_object_type(dispatcher, command):
    """Prompt user for type of object to validate."""
    dispatcher.prompt_from_menu(
        command, "Select an allowed object type", [(object_type, object_type) for object_type in ALLOWED_OBJECTS]
    )
    return CommandStatusChoices.STATUS_SUCCEEDED


def prompt_for_nautobot_device(dispatcher, command):
    """Prompt user for firewall device within Nautobot."""
    _devices = Device.objects.all()
    dispatcher.prompt_from_menu(command, "Select a Nautobot Device", [(dev.name, str(dev.id)) for dev in _devices])
    return CommandStatusChoices.STATUS_SUCCEEDED


def prompt_for_device(dispatcher, command, conn):
    """Prompt the user to select a Palo Alto device."""
    _devices = get_devices(connection=conn)
    dispatcher.prompt_from_menu(command, "Select a Device", [(dev, dev) for dev in _devices])
    return CommandStatusChoices.STATUS_SUCCEEDED


def prompt_for_versions(dispatcher, command, conn, prompt_offset=None):
    """Prompt the user to select a version."""
    conn.software.check()
    versions = conn.software.versions
    if prompt_offset:
        prompt_offset = int(prompt_offset)
    dispatcher.prompt_from_menu(command, "Select a Version", [(ver, ver) for ver in versions][prompt_offset:])
    return CommandStatusChoices.STATUS_SUCCEEDED


def is_valid_cidr(ip_address: str) -> str:
    """Checks if string is a valid IPv4 CIDR."""
    try:
        return str(ip_network(str(ip_address)))
    except ValueError:
        return ""


@job("default")
def panorama(subcommand, **kwargs):
    """Perform panorama and its subcommands."""
    return handle_subcommands("panorama", subcommand, **kwargs)


@subcommand_of("panorama")
def validate_rule_exists(
    dispatcher, device, src_ip, dst_ip, protocol, dst_port
):  # pylint:disable=too-many-arguments,too-many-locals,too-many-branches
    """Verify that the rule exists within a device, via Panorama."""
    dialog_list = [
        {
            "type": "text",
            "label": "Source IP",
        },
        {
            "type": "text",
            "label": "Destination IP",
        },
        {
            "type": "select",
            "label": "Dest IP",
            "choices": [("TCP", "TCP"), ("UDP", "UDP")],
            "default": ("TCP", "TCP"),
        },
        {
            "type": "text",
            "label": "Destination dst_port",
            "default": "443",
        },
    ]

    if all([device, src_ip, dst_ip, protocol, dst_port]):
        dispatcher.send_markdown(
            f"Standby {dispatcher.user_mention()}, I'm checking the firewall rules now. ",
            ephemeral=True,
        )

    pano = connect_panorama()
    if not device:
        return prompt_for_device(dispatcher, "panorama validate-rule-exists", pano)

    if not all([src_ip, dst_ip, protocol, dst_port]):
        dispatcher.multi_input_dialog(
            "panorama", f"validate-rule-exists {device}", "Verify if rule exists", dialog_list
        )
        return CommandStatusChoices.STATUS_SUCCEEDED

    # Validate IP addresses are valid or 'any' is used.
    # TODO: Add support for hostnames
    if not is_valid_cidr(src_ip) and src_ip.lower() != "any":
        dispatcher.send_warning(
            f"Source IP {src_ip} is not a valid host or CIDR. Please specify a valid host IP address or IP network in CIDR notation."
        )
        dispatcher.multi_input_dialog(
            "panorama", f"validate-rule-exists {device}", "Verify if rule exists", dialog_list
        )
        return CommandStatusChoices.STATUS_ERRORED

    if not is_valid_cidr(dst_ip) and src_ip.lower() != "any":
        dispatcher.send_warning()
        dispatcher.multi_input_dialog(
            "panorama", f"validate-rule-exists {device}", "Verify if rule exists", dialog_list
        )
        return CommandStatusChoices.STATUS_ERRORED

    serial = get_devices(connection=pano).get(device, {}).get("serial")
    if not serial:
        return dispatcher.send_warning(f"The device {device} was not found.")

    data = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": PROTO_NAME_TO_NUM.get(protocol.upper()),
        "dst_port": dst_port,
    }
    matching_rules = get_rule_match(five_tuple=data, serial=serial)

    if matching_rules:
        all_rules = []
        for rule in get_all_rules(device, pano):
            if rule.name == matching_rules[0]["name"]:
                rule_list = []
                rule_list.append(rule.name)
                sources = ""
                for src in rule.source:
                    sources += src + ", "
                rule_list.append(sources[:-2])
                destination = ""
                for dst in rule.destination:
                    destination += dst + ", "
                rule_list.append(destination[:-2])
                service = ""
                for svc in rule.service:
                    service += svc + ", "
                rule_list.append(service[:-2])
                rule_list.append(rule.action)
                all_rules.append(rule_list)
        blocks = [
            *dispatcher.command_response_header(
                "panorama",
                "validate-rule-exists",
                [
                    ("Device", device),
                    ("Source IP", src_ip),
                    ("Destination IP", dst_ip),
                    ("Protocol", protocol.upper()),
                    ("Destination Port", dst_port),
                ],
                "validated rule",
                palo_logo(dispatcher),
            ),
        ]
        dispatcher.send_blocks(blocks)
        dispatcher.send_markdown(f"The Traffic is permitted via a rule named `{matching_rules[0]['name']}`:")
        dispatcher.send_large_table(("Name", "Source", "Destination", "Service", "Action"), all_rules)
    else:
        blocks = [
            *dispatcher.command_response_header(
                "panorama",
                "validate-rule-exists",
                [
                    ("Device", device),
                    ("Source IP", src_ip),
                    ("Destination IP", dst_ip),
                    ("Protocol", protocol.upper()),
                    ("Destination Port", dst_port),
                ],
                "rule validation",
                palo_logo(dispatcher),
            ),
        ]
        dispatcher.send_blocks(blocks)
        dispatcher.send_markdown("`No matching rule` found for:")
        all_values = [
            ["Device", device],
            ["Source IP", src_ip],
            ["Destination", dst_ip],
            ["Protocol", protocol],
            ["Destination Port", dst_port],
        ]
        dispatcher.send_large_table(("Object", "Value"), all_values)
    return CommandStatusChoices.STATUS_SUCCEEDED


@subcommand_of("panorama")
def get_version(dispatcher):
    """Obtain software version information for Panorama."""
    dispatcher.send_markdown(
        f"Standby {dispatcher.user_mention()}, I'm getting Panorama's version for you.",
        ephemeral=True,
    )
    pano = connect_panorama()
    version = pano.refresh_system_info().version
    blocks = [
        *dispatcher.command_response_header(
            "panorama",
            "get-version",
            [],
            "Panorama version",
            palo_logo(dispatcher),
        )
    ]
    dispatcher.send_blocks(blocks)
    dispatcher.send_markdown(f"The version of Panorama is {version}.")
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
        return prompt_for_versions(dispatcher, f"panorama upload-software {device}", pano)

    if "menu_offset" in version:
        return prompt_for_versions(
            dispatcher, f"panorama upload-software {device}", pano, prompt_offset=re.findall(r"\d+", version)[0]
        )

    devs = get_devices(connection=pano)
    dispatcher.send_markdown(
        f"Hey {dispatcher.user_mention()}, you've requested to upload {version} to {device}.", ephemeral=True
    )
    _firewall = Firewall(serial=devs[device]["serial"])
    pano.add(_firewall)
    dispatcher.send_markdown("Starting download now...", ephemeral=True)
    try:
        _firewall.software.download(version)
    except PanDeviceError as err:
        blocks = [
            *dispatcher.command_response_header(
                "panorama",
                "upload-software",
                [("Device", device), ("Version", version)],
                "information on that upload software task",
                palo_logo(dispatcher),
            ),
        ]
        dispatcher.send_blocks(blocks)
        dispatcher.send_warning(f"There was an issue uploading {version} to {device}. {err}")
        return CommandStatusChoices.STATUS_SUCCEEDED
    blocks = [
        *dispatcher.command_response_header(
            "panorama",
            "upload-software",
            [("Device", device), ("Version", version)],
            "information on that upload software task",
            palo_logo(dispatcher),
        ),
    ]
    dispatcher.send_blocks(blocks)
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

    if "menu_offset" in version:
        return prompt_for_versions(
            dispatcher, f"panorama upload-software {device}", pano, prompt_offset=re.findall(r"\d+", version)[0]
        )

    devs = get_devices(connection=pano)
    dispatcher.send_markdown(
        f"Hey {dispatcher.user_mention()}, you've requested to install {version} to {device}.", ephemeral=True
    )
    _firewall = Firewall(serial=devs[device]["serial"])
    pano.add(_firewall)
    try:
        _firewall.software.install(version)
    except PanDeviceError as err:
        blocks = [
            *dispatcher.command_response_header(
                "panorama",
                "install-software",
                [("Device", device), ("Version", version)],
                "information on that install software task",
                palo_logo(dispatcher),
            ),
        ]
        dispatcher.send_blocks(blocks)
        dispatcher.send_warning(f"There was an issue installing {version} on {device}. {err}")
        return CommandStatusChoices.STATUS_FAILED
    blocks = [
        *dispatcher.command_response_header(
            "panorama",
            "install-software",
            [("Device", device), ("Version", version)],
            "information on that install software task",
            palo_logo(dispatcher),
        ),
    ]
    dispatcher.send_blocks(blocks)
    dispatcher.send_markdown(f"As requested, {version} has been installed on {device}.")
    return CommandStatusChoices.STATUS_SUCCEEDED


@subcommand_of("panorama")
def get_device_rules(dispatcher, device, **kwargs):
    """Get list of firewall rules with details."""
    pano = connect_panorama()
    if not device:
        return prompt_for_device(dispatcher, "panorama get-device-rules", pano)

    dispatcher.send_markdown(
        f"Standby {dispatcher.user_mention()}, I'm getting the rules for device {device}.",
        ephemeral=True,
    )

    rules = get_all_rules(device, pano)

    all_rules = []
    for rule in rules:
        rule_list = []
        rule_list.append(rule.name)
        sources = ""
        for src in rule.source:
            sources += src + ", "
        rule_list.append(sources[:-2])
        destination = ""
        for dst in rule.destination:
            destination += dst + ", "
        rule_list.append(destination[:-2])
        service = ""
        for svc in rule.service:
            service += svc + ", "
        rule_list.append(service[:-2])
        rule_list.append(rule.action)
        all_rules.append(rule_list)

    blocks = [
        *dispatcher.command_response_header(
            "panorama",
            "get-device-rules",
            [("Device", device)],
            f"rules for device {device}",
            palo_logo(dispatcher),
        ),
    ]
    dispatcher.send_blocks(blocks)
    dispatcher.send_large_table(("Name", "Source", "Destination", "Service", "Action"), all_rules)
    return CommandStatusChoices.STATUS_SUCCEEDED


@subcommand_of("panorama")
def export_device_rules(dispatcher, device, **kwargs):
    """Generate list of firewall rules with details in CSV format."""
    if device:
        dispatcher.send_markdown(
            f"Standby {dispatcher.user_mention()}, I'm creating the CSV file for the rules on device {device}.",
            ephemeral=True,
        )
    else:
        pano = connect_panorama()
        return prompt_for_device(dispatcher, "panorama export-device-rules", pano)
    logger.debug("Running /panorama export-device-rules, device=%s", device)

    pano = connect_panorama()
    rules = get_all_rules(device, pano)

    file_name = f"{device}-device-rules.csv"

    output = split_rules(rules)
    with open(file_name, "w") as file:  # pylint: disable=unspecified-encoding
        file.write(output)

    dispatcher.send_image(file_name)

    try:
        os.remove(file_name)
        logger.debug("Deleted generated CSV file %s", file_name)
    except FileNotFoundError:
        logger.warning("Unable to delete generated CSV file %s", file_name)

    return CommandStatusChoices.STATUS_SUCCEEDED


@subcommand_of("panorama")
def capture_traffic(
    dispatcher: object,
    device: str,
    snet: str,
    dnet: str,
    dport: str,
    intf_name: str,
    ip_proto: str,
    stage: str,
    capture_seconds: str,
    **kwargs,
):  # pylint:disable=too-many-arguments,too-many-return-statements,too-many-locals,too-many-branches
    """Capture IP traffic on PANOS Device.

    Args:
        dispatcher (object): Chatops plugin dispatcher object
        device (str): Device name
        snet (str): Source IP/network in IPv4 CIDR notation
        dnet (str): Destination IP/network in IPv4 CIDR notation
        dport (str): Destination port
        intf_name (str): Interface name
        ip_proto (str): Protocol for destination port
        stage (str): Stage to use
        capture_seconds (str): Number of seconds to run packet capture

    """
    logger.info("Starting packet capture")

    if all([device, snet, dnet, dport, intf_name, ip_proto, stage, capture_seconds]):
        dispatcher.send_markdown(
            f"Standby {dispatcher.user_mention()}, I'm starting the packet capture on device {device}.",
            ephemeral=True,
        )

    # ---------------------------------------------------
    # Get device to execute against
    # ---------------------------------------------------
    pano = connect_panorama()

    if not device:
        return prompt_for_device(dispatcher, "panorama capture-traffic", pano)

    # ---------------------------------------------------
    # Get parameters used to filter packet capture
    # ---------------------------------------------------
    _interfaces = Interface.objects.filter(device__name=device)
    dialog_list = [
        {
            "type": "text",
            "label": "Source Network",
            "default": "0.0.0.0/0",
        },
        {
            "type": "text",
            "label": "Destination Network",
            "default": "0.0.0.0/0",
        },
        {
            "type": "text",
            "label": "Destination Port",
            "default": "any",
        },
        {
            "type": "select",
            "label": "Interface Name",
            "choices": [(intf.name, intf.name) for intf in _interfaces],
            "confirm": False,
        },
        {
            "type": "select",
            "label": "IP Protocol",
            "choices": [("ANY", "any"), ("TCP", "6"), ("UDP", "17")],
            "confirm": False,
            "default": ("ANY", "any"),
        },
        {
            "type": "select",
            "label": "Capture Stage",
            "choices": [("Receive", "receive"), ("Transmit", "transmit"), ("Drop", "drop"), ("Firewall", "firewall")],
            "confirm": False,
            "default": ("Receive", "receive"),
        },
        {
            "type": "text",
            "label": "Capture Seconds",
            "default": "15",
        },
    ]

    if not all([snet, dnet, dport, intf_name, ip_proto, stage, capture_seconds]):
        dispatcher.multi_input_dialog("panorama", f"capture-traffic {device}", "Capture Filter", dialog_list)
        return CommandStatusChoices.STATUS_SUCCEEDED

    logger.debug(
        "Running packet capture with the following information:\nDevice - %s\nSource Network - %s\nDestination Network - %s\nDestination Port - %s\nInterface Name - %s\nIP Protocol - %s\nStage - %s\nCapture Seconds - %s",
        device,
        snet,
        dnet,
        dport,
        intf_name,
        ip_proto,
        stage,
        capture_seconds,
    )

    # ---------------------------------------------------
    # Validate dialog list
    # ---------------------------------------------------
    try:
        ip_network(snet)
    except ValueError:
        dispatcher.send_warning(
            f"Source Network {snet} is not a valid CIDR, please specify a valid network in CIDR notation"
        )
        return CommandStatusChoices.STATUS_FAILED

    try:
        ip_network(dnet)
    except ValueError:
        dispatcher.send_warning(
            f"Destination Network {dnet} is not a valid CIDR, please specify a valid network in CIDR notation"
        )
        return CommandStatusChoices.STATUS_FAILED

    dport_init_val = deepcopy(dport)
    try:
        dport = int(dport)
        if dport < 1 or dport > 65535:
            raise TypeError
    except ValueError:
        # Port may be a string, which is still valid
        if dport.lower() == "any":
            dport = None
    except (AttributeError, TypeError):
        dispatcher.send_warning(
            f"Destination Port {dport} must be either the string `any` or an integer in the range 1-65535"
        )
        return CommandStatusChoices.STATUS_FAILED

    ip_proto_init_val = deepcopy(ip_proto)
    if ip_proto == "any":
        ip_proto = None

    capture_seconds_init_val = deepcopy(capture_seconds)
    try:
        capture_seconds = int(capture_seconds)
        if capture_seconds > 120 or capture_seconds < 1:
            raise ValueError
    except ValueError:
        dispatcher.send_warning("Capture Seconds must be specified as a number in the range 1-120")
        return CommandStatusChoices.STATUS_FAILED

    # ---------------------------------------------------
    # Start Packet Capture on Device
    # ---------------------------------------------------
    try:
        device_ip = Device.objects.get(name=device).custom_field_data["public_ipv4"]
        logger.info("Attempting packet capture to device %s via public IP address %s.", device, device_ip)
    except KeyError:
        logger.warning("No Public IPv4 address assigned to device %s in Nautobot.", device)
        device_ip = Device.objects.get(name=device).primary_ip4
        logger.info("Attempting packet capture to device %s via primary IP address %s.", device, device_ip)

    # Convert IPAddress model type to string
    device_ip = str(device_ip)

    # Name of capture file
    capture_filename = f"{device}-packet-capture.pcap"

    # Begin packet capture on device
    start_packet_capture(
        capture_filename,
        device_ip,
        {
            "snet": snet.split("/")[0],
            "scidr": snet.split("/")[1],
            "dnet": dnet.split("/")[0],
            "dcidr": dnet.split("/")[1],
            "dport": dport,
            "intf_name": intf_name,
            "ip_proto": ip_proto,
            "stage": stage,
            "capture_seconds": capture_seconds,
        },
    )

    blocks = [
        *dispatcher.command_response_header(
            "panorama",
            "capture-traffic",
            [("Details below:", " ")],
            "PCAP file",
            palo_logo(dispatcher),
        ),
    ]

    dispatcher.send_blocks(blocks)

    all_values = [
        ["Device", device],
        ["Source Network", snet],
        ["Destination Network", dnet],
        ["Destination Port", dport_init_val],
        ["Interface Name", intf_name],
        ["IP Protocol", ip_proto_init_val],
        ["Stage", stage],
        ["Capture Seconds", capture_seconds_init_val],
    ]
    dispatcher.send_large_table(("Object", "Value"), all_values)
    return dispatcher.send_image(capture_filename)
