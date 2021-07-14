from nautobot_plugin_chatops_panorama.constant import PLUGIN_CFG

from panos.panorama import Panorama
from panos.firewall import Firewall
from panos.device import SystemSettings
from nautobot_plugin_chatops_panorama.constant import PLUGIN_CFG

from requests.exceptions import RequestException

import defusedxml.ElementTree as ET

import requests
from netmiko import ConnectHandler
import time

def get_api_key_api(url: str = PLUGIN_CFG["panorama_host"]) -> str:
    """Returns the API key.
    Args:
        url (str): URL of the device
    Returns:
        The API key.
    """
    url = url.rstrip("/")

    params = {"type": "keygen", "user": PLUGIN_CFG["panorama_user"], "password": PLUGIN_CFG["panorama_password"]}

    response = requests.get(f"{url}/api/", params=params)
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


def _get_group(groups, serial):
    """Sort through fetched groups and serials and return group.

    Args:
        groups (dict): Group names as keys and serial numbers in a list
        serial (str): Serial to search for within group serial number lists

    Returns:
        group_name (str): Name of group serial is part of or None if serial not in a group
    """
    for k, v in groups.items():
        if serial in v:
            return k


def get_devices(connection: Panorama) -> dict:
    """Method to obtain the devices connected to Panorama.

    Args:
        connection (Panorama): Connection object to Panorama.

    Returns:
        dict: Dictionary of all devices attached to Panorama.
    """
    dev_list = connection.refresh_devices(expand_vsys=False, include_device_groups=False)

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


def start_packet_capute(ip: str, commands: dict):
    """Starts or stops packet capturing on the Managed FW.

    Args:
        ip (str): IP address of the device
        commands (dict): Commands to pass to the device for packet capturing

    """

    dev_connect = {
        'device_type': 'paloalto_panos',
        'host': ip,
        'username': PLUGIN_CFG["panorama_user"],
        'password': PLUGIN_CFG["panorama_password"]
    }

    ssh = ConnectHandler(**dev_connect)
    ssh.send_command("debug dataplane packet-diag clear all")
    ssh.send_command("delete debug-filter file python.pcap")

    ssh.send_command("debug dataplane packet-diag set filter index 1 match ingress-interface ethernet1/2")
    ssh.send_command("debug dataplane packet-diag set filter on")
    ssh.send_command("debug dataplane packet-diag set capture stage receive byte-count 1024 file python.pcap")
    ssh.send_command("debug dataplane packet-diag set capture on")
    time.sleep(60)
    ssh.send_command("debug dataplane packet-diag set capture off")
    ssh.send_command("debug dataplane packet-diag set filter off")


def _get_pcap(ip:str):
    """Downloads PCAP file from PANOS device

    Args:
        ip (str): IP address of the device
    """

    url = f"https://{ip}/api/"

    params = {
        "key": get_api_key_api(),
        "type": "export",
        "category": "filters-pcap",
        "from": "1.pcap"
    }

    respone = requests.get(url, params=params, verify=False)

    with open("capture.pcap", "wb") as pcap_file:
        pcap_file.write(respone.content)