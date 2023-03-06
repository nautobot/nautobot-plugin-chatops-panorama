"""Functions used for interacting with Panroama."""
import logging
import time

import defusedxml.ElementTree as ET
import requests

from netmiko import ConnectHandler
from panos.errors import PanDeviceXapiError
from panos.firewall import Firewall
from panos.panorama import Panorama
from panos.policies import Rulebase, SecurityRule
from requests.exceptions import RequestException

from nautobot_plugin_chatops_panorama.constant import PLUGIN_CFG


logger = logging.getLogger(__name__)


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


def get_devices_from_pano(connection: Panorama) -> dict:
    """Method to obtain the devices connected to Panorama.

    Args:
        connection (Panorama): Connection object to Panorama.

    Returns:
        dict: Dictionary of all devices attached to Panorama.
    """
    _device_dict = {}
    devicegroups = connection.refresh_devices()
    for group in devicegroups:
        for device in group.children:
            try:
                connection.add(device)
                device_system_info = device.show_system_info()["system"]
                # TODO: Add support for virtual firewall (vsys PA's) on same physical device
                _device_dict[device_system_info["hostname"]] = {
                    "hostname": device_system_info["hostname"],
                    "serial": device_system_info["serial"],
                    "group_name": group.name,
                    "ip_address": device_system_info["ip-address"],
                    "status": device.is_active(),
                    "model": device_system_info["model"],
                    "os_version": device_system_info["sw-version"],
                }
            except PanDeviceXapiError as err:
                logger.warning("Unable to pull info for %s. %s", device, err)
    return _device_dict


def get_devicegroups_from_pano(connection: Panorama) -> dict:
    """Method to obtain DeviceGroups and associated information for devices."""
    _group_dict = {}
    devicegroups = connection.refresh_devices()
    for group in devicegroups:
        if group.name not in _group_dict:
            _group_dict[group.name] = {"devices": []}
        for device in group.children:
            dev = None
            try:
                connection.add(device)
                dev = device.show_system_info()["system"]
            except PanDeviceXapiError as err:
                logger.warning("Unable to pull info for %s. %s", device, err)
            if dev:
                _group_dict[group.name]["devices"].append(
                    {
                        "hostname": dev["hostname"],
                        "address": dev["ip-address"],
                        "serial": dev["serial"],
                        "model": dev["model"],
                        "version": dev["sw-version"],
                    }
                )
    return _group_dict


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

    # Ignore this command if not filtering by port (when user sets port to 'any')
    if filters["dport"] and filters["dport"] != "any":
        command += f" destination-port {filters['dport']}"

    if filters["dnet"] != "0.0.0.0":  # nosec
        command += f" destination {filters['dnet']}"
        if filters["dcidr"] != "0":
            command += f" destination-netmask {filters['dcidr']}"

    if filters["snet"] != "0.0.0.0":  # nosec
        command += f" source {filters['snet']}"
        if filters["scidr"] != "0":
            command += f" source-netmask {filters['scidr']}"

    # Ignore this command if not filtering by port (when user sets protocol to 'any')
    if filters["ip_proto"] and filters["ip_proto"] != "any":
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


def get_all_rules(device_name: str, pano: Panorama) -> list:
    """Get all currently configured rules.

    Args:
        device_name (str): Name of firewall device in Panorama
        pano (Panorama): Panorama connection

    Returns:
        list: List of rules
    """
    firewalls = pano.refresh_devices(include_device_groups=False)
    device = None
    for firewall in firewalls:
        try:
            pano.add(firewall)
            dev = firewall.show_system_info()["system"]
            if dev["hostname"] == device_name:
                device = firewall
        except PanDeviceXapiError as err:
            logger.warning("Unable to pull info for %s. %s", device_name, err)
    dev = pano.add(device)
    rulebase = dev.add(Rulebase())
    try:
        rules = SecurityRule.refreshall(rulebase)
    except PanDeviceXapiError as err:
        logger.warning("Unable to find information about %s as it's not connected to Panorama. %s", device, err)
        rules = []
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

def get_object(pano: Panorama, object_name: str):
    """Searches Panorama inventory for provided object name and returns either a DeviceGroup or Firewall object if name matches.

    Args:
        pano (Panorama): Connection to Panorama.
        object_name (str): Name of either a Firewall or DeviceGroup to find and return.

    Returns:
        DeviceGroup|Firewall: Either a Firewall or DeviceGroup object if found.
    """
    object_index = {}
    dev_groups = pano.refresh_devices()
    for instance in dev_groups:
        if isinstance(instance, DeviceGroup):
            group_name = f"{instance.name} (DeviceGroup)"
            object_index[group_name] = instance
            if instance.children:
                for child in instance.children:
                    if isinstance(child, Firewall):
                        try:
                            pano.add(child)
                            info = child.show_system_info()["system"]
                            object_index[info["hostname"]] = child
                        except PanDeviceXapiError as err:
                            logger.warning(f"Unable to connect to {child}. {err}")
        if isinstance(instance, Firewall):
            pano.add(instance)
            info = instance.show_system_info()["system"]
            object_index[info["hostname"]] = instance

    if object_name in object_index:
        return object_index[object_name]
    return None

