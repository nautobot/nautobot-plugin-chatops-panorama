"""Example rq worker to handle /panorama chat commands with 1 subcommand addition."""
import logging
import os
import re
from ipaddress import ip_network

from django_rq import job
from nautobot.dcim.models import Device, Interface
from nautobot.ipam.models import Service
from nautobot_chatops.choices import CommandStatusChoices
from nautobot_chatops.workers import handle_subcommands, subcommand_of

from panos.panorama import DeviceGroup
from panos.firewall import Firewall
from panos.errors import PanDeviceError

from nautobot_plugin_chatops_panorama.constant import UNKNOWN_SITE, ALLOWED_OBJECTS
from nautobot_plugin_chatops_panorama.utils.nautobot import (
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
    get_rule_match,
    start_packet_capture,
    get_all_rules,
    split_rules,
)


logger = logging.getLogger("rq.worker")


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
):  # pylint:disable=too-many-arguments,too-many-locals
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
            "choices": [("TCP", "6"), ("UDP", "17")],
            "default": ("TCP", "6"),
        },
        {
            "type": "text",
            "label": "Destination dst_port",
            "default": "443",
        },
    ]

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
        dispatcher.send_markdown(
            f"Source IP {src_ip} is not a valid host or CIDR. Please specify a valid host IP address or IP network in CIDR notation."
        )
        dispatcher.multi_input_dialog(
            "panorama", f"validate-rule-exists {device}", "Verify if rule exists", dialog_list
        )
        return CommandStatusChoices.STATUS_ERRORED

    if not is_valid_cidr(dst_ip) and src_ip.lower() != "any":
        dispatcher.send_markdown(
            f"Destination IP {dst_ip} is not a valid host or CIDR. Please specify a valid host IP address or IP network in CIDR notation."
        )
        dispatcher.multi_input_dialog(
            "panorama", f"validate-rule-exists {device}", "Verify if rule exists", dialog_list
        )
        return CommandStatusChoices.STATUS_ERRORED

    serial = get_devices(connection=pano).get(device, {}).get("serial")
    if not serial:
        return dispatcher.send_markdown(f"The device {device} was not found.")

    data = {"src_ip": src_ip, "dst_ip": dst_ip, "protocol": protocol, "dst_port": dst_port}
    matching_rules = get_rule_match(five_tuple=data, serial=serial)

    if matching_rules:
        all_rules = list()
        for rule in get_all_rules(device):
            if rule.name == matching_rules[0]["name"]:
                rule_list = list()
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
        dispatcher.send_markdown(f"The Traffic is permitted via a rule named `{matching_rules[0]['name']}`:")
        dispatcher.send_large_table(("Name", "Source", "Destination", "Service", "Action"), all_rules)
    else:
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
        return prompt_for_versions(dispatcher, f"panorama upload-software {device}", pano)

    if "menu_offset" in version:
        return prompt_for_versions(dispatcher, f"panorama upload-software {device}", pano, prompt_offset=re.findall(r'\d+', version)[0])

    devs = get_devices(connection=pano)
    dispatcher.send_markdown(f"Hey {dispatcher.user_mention()}, you've requested to upload {version} to {device}.")
    _firewall = Firewall(serial=devs[device]["serial"])
    pano.add(_firewall)
    dispatcher.send_markdown("Starting download now...")
    try:
        _firewall.software.download(version)
    except PanDeviceError as err:
        dispatcher.send_markdown(f"There was an issue uploading {version} to {device}. {err}")
        return CommandStatusChoices.STATUS_SUCCEEDED
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
        return prompt_for_versions(dispatcher, f"panorama upload-software {device}", pano, prompt_offset=re.findall(r'\d+', version)[0])

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
        # logic to create device type based on model
        device_type = _get_or_create_device_type(data["model"])
        # logic to create device
        device = _get_or_create_device(
            name, data["group_name"], device_type, serial=data["serial"], os_description=data["os_version"]
        )
        # # logic to create interfaces
        interfaces = _get_or_create_interfaces(device)
        # # logic to assign ip_address to mgmt interface
        mgmt_ip = _get_or_create_management_ip(device, interfaces, data["ip_address"])
        # Add info for device creation to be sent to table creation at the end of task
        status = (name, data["group_name"], device_type, mgmt_ip, ", ".join([intf.name for intf in interfaces]))
        device_status.append(status)
    dispatcher.send_large_table(("Name", "Site", "Type", "Primary IP", "Interfaces"), device_status)
    return CommandStatusChoices.STATUS_SUCCEEDED


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
    for service in services:
        computed_fields = service.get_computed_fields()

        if object_type in ["address", "all"]:
            computed_objects = computed_fields.get("address_objects")
            obj_names = set(computed_objects.split(", "))
            current_objs = obj_names.difference(names)
            names.update(current_objs)
            if computed_objects:
                object_results.extend(compare_address_objects(current_objs, pano))

        if object_type in ["service", "all"]:
            computed_objects = computed_fields.get("service_objects")
            obj_names = set(computed_objects.split(", "))
            current_objs = obj_names.difference(names)
            names.update(current_objs)
            if computed_objects:
                object_results.extend(compare_service_objects(current_objs, pano))

    dispatcher.send_large_table(("Name", "Object Type", "Status (Nautobot/Panorama)"), object_results)
    return CommandStatusChoices.STATUS_SUCCEEDED


@subcommand_of("panorama")
def get_device_rules(dispatcher, device, **kwargs):
    """Get list of firewall rules with details."""
    if not device:
        return prompt_for_nautobot_device(dispatcher, "panorama get-device-rules")

    rules = get_all_rules(device)

    all_rules = list()
    for rule in rules:
        rule_list = list()
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

    dispatcher.send_large_table(("Name", "Source", "Destination", "Service", "Action"), all_rules)
    return CommandStatusChoices.STATUS_SUCCEEDED


@subcommand_of("panorama")
def export_device_rules(dispatcher, device, **kwargs):
    """Get list of firewall rules with details."""
    if not device:
        return prompt_for_nautobot_device(dispatcher, "panorama export-device-rules")
    logger.debug("Running /panorama export-device-rules, device=%s", device)

    rules = get_all_rules(device)

    file_name = "device_rules.csv"

    output = split_rules(rules)
    with open(file_name, "w") as file:
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
):  # pylint:disable=too-many-arguments,too-many-return-statements
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
            "choices": [("TCP", "6"), ("UDP", "17"), ("ANY", "any")],
            "confirm": False,
            "default": ("TCP", "6"),
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
        dispatcher.send_markdown(
            f"Source Network {snet} is not a valid CIDR, please specify a valid network in CIDR notation"
        )
        return CommandStatusChoices.STATUS_FAILED

    try:
        ip_network(dnet)
    except ValueError:
        dispatcher.send_markdown(
            f"Destination Network {dnet} is not a valid CIDR, please specify a valid network in CIDR notation"
        )
        return CommandStatusChoices.STATUS_FAILED

    try:
        dport = int(dport)
        if dport < 1 or dport > 65535:
            raise ValueError
    except ValueError:
        # Port may be a string, which is still valid
        if dport.lower() == "any":
            dport = None
    except (AttributeError, TypeError):
        dispatcher.send_markdown(
            f"Destination Port {dport} must be either the string `any` or an integer in the range 1-65535"
        )
        return CommandStatusChoices.STATUS_FAILED

    if ip_proto == "any":
        ip_proto = None

    try:
        capture_seconds = int(capture_seconds)
        if capture_seconds > 120 or capture_seconds < 1:
            raise ValueError
    except ValueError:
        dispatcher.send_markdown("Capture Seconds must be specified as a number in the range 1-120")
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

    dispatcher.send_markdown(f"Starting {capture_seconds} second packet capture")
    start_packet_capture(
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

    dispatcher.send_markdown("Here is the PCAP file that your requested!")
    return dispatcher.send_image("captured.pcap")
