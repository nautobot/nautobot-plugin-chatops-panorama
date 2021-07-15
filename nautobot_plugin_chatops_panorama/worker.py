"""Example rq worker to handle /panorama chat commands with 1 subcommand addition."""
import logging
import requests

from django_rq import job
from nautobot.dcim.models import Device, Interface
from nautobot.ipam.models import Service
from nautobot_chatops.choices import CommandStatusChoices
from nautobot_chatops.workers import handle_subcommands, subcommand_of
import json
import defusedxml.ElementTree as ET


from panos.panorama import DeviceGroup
from panos.firewall import Firewall
from panos.errors import PanDeviceError

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
    get_api_key_api,
    get_rule_match,
    parse_all_rule_names,
    start_packet_capture,
    get_all_rules,
    split_rules
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
def validate_rule_exists(dispatcher, device, src_ip, dst_ip, protocol, dst_port):
    """Verify that the rule exists within a device, via Panorama."""

    dialog_list = [
        {
            "type": "text",
            "label": "Device",
        },
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
    if not all([device, src_ip, dst_ip, protocol, dst_port]):
        dispatcher.multi_input_dialog("panorama", "validate-rule-exists", "Verify if rule exists", dialog_list)
        return CommandStatusChoices.STATUS_SUCCEEDED

    pano = connect_panorama()
    serial = get_devices(connection=pano).get(device, {}).get("serial")
    if not serial:
        return dispatcher.send_markdown(f"The device {device} was not found.")

    data = {"src_ip":src_ip, "dst_ip": dst_ip, "protocol": protocol, "dst_port": dst_port}
    xml_rules = get_rule_match(connection=pano, five_tuple=data, serial=serial)

    root = ET.fromstring(xml_rules)
    if len(root.findall('.//entry')) == 0:
        dispatcher.send_markdown(f"No matching rule found.")
    else:
        dispatcher.send_markdown(f"The version of Panorama is {split_rules(xml_rules)}.")
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

    dispatcher.send_large_table(("Name", "Object Type", "Status (Nautobot/Panorama)"), object_results)
    return CommandStatusChoices.STATUS_SUCCEEDED


@subcommand_of("panorama")
def get_pano_rules(dispatcher, **kwargs):
    """Get list of firewall rules by name."""
    logger.info("Pulling list of firewall rules by name.")
    pano = connect_panorama()
    # if not device:
    #     return prompt_for_nautobot_device(dispatcher, "panorama get-rules")
    # device = Device.objects.get(id=device)
    api_key = get_api_key_api()
    params = {
        "key": api_key,
        "cmd": """
            <show>
                <rule-hit-count>
                    <device-group>
                        <entry name="Demo">
                            <pre-rulebase>
                            <entry name="security">
                                <rules>
                                    <all/>
                                </rules>
                            </entry>
                            </pre-rulebase>
                        </entry>
                    </device-group>
                </rule-hit-count>
            </show>""",
        "type": "op",
    }
    host = PLUGIN_CFG["panorama_host"].rstrip("/")
    url = f"https://{host}/api/"
    response = requests.get(url, params=params, verify=False)
    if not response.ok:
        dispatcher.send_markdown(f"Error retrieving device rules.")
        return CommandStatusChoices.STATUS_FAILED

    rule_names = parse_all_rule_names(response.text)
    return_str = ""
    for idx, name in enumerate(rule_names):
        return_str += f"Rule {idx+1}\t\t{name}\n"
    dispatcher.send_markdown(return_str)
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

    rules = get_all_rules(device)

    output = split_rules(rules)

    # dispatcher.snippet(output)
    dispatcher.send_snippet(output)
    return CommandStatusChoices.STATUS_SUCCEEDED


@subcommand_of("panorama")
def export_device_rules_csv(dispatcher, device, **kwargs):
    """Get list of firewall rules with details."""
    if not device:
        return prompt_for_nautobot_device(dispatcher, "panorama export-device-rules")

    rules = get_all_rules(device)

    file_name = "device_rules.csv"

    output = split_rules(rules)
    with open(file_name, "w") as f:
        f.write(output)

    # dispatcher.snippet(output)
    dispatcher.send_image(file=file_name)
    return CommandStatusChoices.STATUS_SUCCEEDED


@subcommand_of("panorama")
def capture_traffic(dispatcher, device_id, snet, dnet, dport, intf_name, ip_proto):
    """Capture IP traffic on PANOS Device."""

    logger.info("Starting packet capturing.")
    _devices = Device.objects.all()

    if not device_id:
        return dispatcher.prompt_from_menu("panorama capture-traffic", "Select Palo-Alto Device", [(dev.name, str(dev.id)) for dev in _devices])

    _interfaces = Interface.objects.filter(device__id=device_id)
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
            "default": ("Ethernet1/1", "ethernet1/1")
        },
        {
            "type": "select",
            "label": "IP Protocol",
            "choices": [("TCP", "6"), ("UDP", "17")],
            "confirm": False,
            "default": ("TCP", "6")
        }
    ]
    # + destination           Destination IP address
    # + destination-netmask   Destination netmask
    # + destination-port      Destination port
    # + ingress-interface     Ingress traffic interface name
    # + ipv6-only             IPv6 packet only
    # + non-ip                Non-IP packet
    # + protocol              IP protocol value
    # + source                Source IP address
    # + source-netmask        Source netmask
    # + source-port           Source port
    # + lacp                  LACP packet # include LACP packets
    if not all([snet, dnet, dport, intf_name, ip_proto]):
        return dispatcher.multi_input_dialog("panorama", "capture-traffic", "Test", dialog_list)


    return dispatcher.send_markdown("WORKS")
    # return dispatcher.send_large_table(("Device ID", "Source", "Destination", "Interface", "Protocol"), [[device_id, snet, dnet, dport, intf_name, ip_proto]])



@subcommand_of("panorama")
def matt(dispatcher, device_id, snet, dnet, dport, **kwargs):
    """Capture IP traffic on PANOS Device

    Args:
        device_id
        snet
        dnet
        dport
        intf_name
        ip_proto
    """
    logger.info("Starting packet capturing.")
    _devices = Device.objects.all()

    if not device_id:
        dispatcher.prompt_from_menu("panorama capture-traffic", "Select Palo-Alto Device", [(dev.name, str(dev.id)) for dev in _devices])
        return CommandStatusChoices.STATUS_SUCCEEDED

    # _interfaces = Interface.objects.filter(device__id=device_id)
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
        # {
        #     "type": "select",
        #     "label": "Interface Name",
        #     "choices": [(intf.name, intf.name) for intf in _interfaces],
        #     "confirm": False,
        #     "default": ("Ethernet1/1", "ethernet1/1")
        # },
        # {
        #     "type": "select",
        #     "label": "IP Protocol",
        #     "choices": [("TCP", "6"), ("UDP", "17")],
        #     "confirm": False,
        #     "default": ("TCP", "6")
        # }
    ]
    # + destination           Destination IP address
    # + destination-netmask   Destination netmask
    # + destination-port      Destination port
    # + ingress-interface     Ingress traffic interface name
    # + ipv6-only             IPv6 packet only
    # + non-ip                Non-IP packet
    # + protocol              IP protocol value
    # + source                Source IP address
    # + source-netmask        Source netmask
    # + source-port           Source port
    # + lacp                  LACP packet # include LACP packets
    if not all([snet, dnet, dport]):
        dispatcher.multi_input_dialog("panorama", "capture-traffic", "Test", dialog_list)
        return CommandStatusChoices.STATUS_SUCCEEDED

    dispatcher.send_markdown("WORKS")
    return CommandStatusChoices.STATUS_SUCCEEDED
    # return dispatcher.send_large_table(("Device ID", "Source", "Destination", "Interface", "Protocol"), [[device_id, snet, dnet, dport, intf_name, ip_proto]])
