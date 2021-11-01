"""Functions used for interacting with Panroama."""

import time

import defusedxml.ElementTree as ET
import requests

from netmiko import ConnectHandler
from panos.firewall import Firewall
from panos.panorama import Panorama
from panos.policies import Rulebase, SecurityRule
from requests.exceptions import RequestException

from nautobot_plugin_chatops_panorama.constant import PLUGIN_CFG


def get_api_key_api(url: str = PLUGIN_CFG["panorama_host"]) -> str:
    """Returns the API key.

    Args:
        url (str): URL of the device

    Returns:
        The API key.
    """
    url = url.rstrip("/")

    params = {"type": "keygen", "user": PLUGIN_CFG["panorama_user"], "password": PLUGIN_CFG["panorama_password"]}

    response = requests.get(f"https://{url}/api/", params=params, verify=False)  # nosec
    if response.status_code != 200:
        raise RequestException(f"Something went wrong while making a request. Reason: {response.text}")

    xml_data = ET.fromstring(response.text)
    return xml_data.find(".//key").text


def connect_panorama() -> Panorama:
    """Method to connect to Panorama instance."""
    pano = Panorama(
        hostname=PLUGIN_CFG["panorama_host"],
        api_username=PLUGIN_CFG["panorama_user"],
        api_password=PLUGIN_CFG["panorama_password"],
    )
    return pano


def _get_group(groups: dict, serial: str) -> str:
    """Sort through fetched groups and serials and return group.

    Args:
        groups (dict): Group names as keys and serial numbers in a list
        serial (str): Serial to search for within group serial number lists

    Returns:
        group_name (str): Name of group serial is part of or None if serial not in a group
    """
    for group_name, serial_numbers in groups.items():
        if serial in serial_numbers:
            return group_name
    return None


def get_rule_match(five_tuple: dict, serial: str) -> dict:
    """Method to obtain the devices connected to Panorama.

    Args:
        five_tuple (dict): Five tuple dictionary for rule lookup
        serial (str): Serial of firewall device to query

    Returns:
        dict: Dictionary of all devices attached to Panorama.
    """
    host = PLUGIN_CFG["panorama_host"].rstrip("/")
    firewall = Firewall(serial=serial)
    pano = Panorama(host, api_key=get_api_key_api())
    pano.add(firewall)
    match = firewall.test_security_policy_match(
        source=five_tuple["src_ip"],
        destination=five_tuple["dst_ip"],
        protocol=int(five_tuple["protocol"]),
        port=int(five_tuple["dst_port"]),
    )
    return match


def get_devices(connection: Panorama) -> dict:
    """Method to obtain the devices connected to Panorama.

    Args:
        connection (Panorama): Connection object to Panorama.

    Returns:
        dict: Dictionary of all devices attached to Panorama.
    """
    dev_list = connection.refresh_devices(include_device_groups=False)

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


def start_packet_capture(capture_filename: str, ip_address: str, filters: dict):
    """Starts or stops packet capturing on the Managed FW.

    Args:
        capture_filename (str): Name of packet capture file
        ip_address (str): IP address of the device
        filters (dict): Commands to pass to the device for packet capturing
    """
    dev_connect = {
        "device_type": "paloalto_panos",
        "host": ip_address,
        "username": PLUGIN_CFG["panorama_user"],
        "password": PLUGIN_CFG["panorama_password"],
    }

    command = f"debug dataplane packet-diag set filter index 1 match ingress-interface {filters['intf_name']}"

    if filters["dport"]:
        command += f" destination-port {filters['dport']}"

    if filters["dnet"] != "0.0.0.0":  # nosec
        command += f" destination {filters['dnet']}"
        if filters["dcidr"] != "0":
            command += f" destination-netmask {filters['dcidr']}"

    if filters["snet"] != "0.0.0.0":  # nosec
        command += f" source {filters['snet']}"
        if filters["scidr"] != "0":
            command += f" source-netmask {filters['scidr']}"

    if filters["ip_proto"]:
        command += f" protocol {filters['ip_proto']}"

    ssh = ConnectHandler(**dev_connect)
    ssh.send_command("debug dataplane packet-diag clear all")
    ssh.send_command("delete debug-filter file python.pcap")

    ssh.send_command(command)
    ssh.send_command("debug dataplane packet-diag set filter on")
    ssh.send_command(
        f"debug dataplane packet-diag set capture stage {filters['stage']}  byte-count 1024 file python.pcap"
    )
    ssh.send_command("debug dataplane packet-diag set capture on")
    time.sleep(int(filters["capture_seconds"]))
    ssh.send_command("debug dataplane packet-diag set capture off")
    ssh.send_command("debug dataplane packet-diag set filter off")
    ssh.disconnect()
    _get_pcap(capture_filename, ip_address)


def _get_pcap(capture_filename: str, ip_address: str):
    """Downloads PCAP file from PANOS device.

    Args:
        capture_filename (str): Name of packet capture file
        ip_address (str): IP address of the device
    """
    url = f"https://{ip_address}/api/"

    params = {"key": get_api_key_api(), "type": "export", "category": "filters-pcap", "from": "1.pcap"}

    respone = requests.get(url, params=params, verify=False)  # nosec

    with open(capture_filename, "wb") as pcap_file:
        pcap_file.write(respone.content)


def parse_all_rule_names(xml_rules: str) -> list:
    """Parse all rules names."""
    rule_names = []
    root = ET.fromstring(xml_rules)
    # Get names of rules
    for i in root.findall(".//entry"):
        name = i.attrib.get("name")
        rule_names.append(name)
    return rule_names


def get_all_rules(device: str, pano: Panorama) -> list:
    """Get all currently configured rules.

    Args:
        device (str): Name of firewall device in Panorama
        pano (Panorama): Panorama connection

    Returns:
        list: List of rules
    """
    devices = pano.refresh_devices(include_device_groups=False)
    device = pano.add(devices[0])
    # TODO: Future - filter by name input, the query/filter in Nautobot DB and/or Panorama
    # if not device:
    #     devices = pano.refresh_devices(expand_vsys=False, include_device_groups=False)
    #     device = pano.add(devices[0])
    rulebase = device.add(Rulebase())
    rules = SecurityRule.refreshall(rulebase)
    return rules


def split_rules(rules, title=""):
    """Split rules into CSV format."""
    output = title or "Name,Source,Destination,Service,Action,To Zone,From Zone\n"
    for rule in rules:
        sources = ""
        for src in rule.source:
            sources += src + " "
        destinations = ""
        for dst in rule.destination:
            destinations += dst + " "
        services = ""
        for svc in rule.service:
            services += svc + " "
        tozone = ""
        for tzone in rule.tozone:
            tozone += tzone + " "
        fromzone = ""
        for fzone in rule.fromzone:
            fromzone += fzone + " "

        output += f"{rule.name},{sources[:-1]},{destinations[:-1]},{services[:-1]},{rule.action},{tozone[:-1]},{fromzone[:-1]}\n"
    return output
