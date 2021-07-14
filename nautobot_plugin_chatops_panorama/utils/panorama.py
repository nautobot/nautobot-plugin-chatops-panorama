from nautobot_plugin_chatops_panorama.constant import PLUGIN_CFG

from panos.panorama import Panorama
from panos.objects import AddressObject, ServiceObject
from panos.errors import PanObjectMissing
from requests.exceptions import RequestException
import defusedxml.ElementTree as ET
import requests


def get_api_key_api(url: str = PLUGIN_CFG["panorama_host"]) -> str:
    """Returns the API key.
    Args:
        url (str): URL of the device
    Returns:
        The API key.
    """
    url = url.rstrip("/")

    params = {"type": "keygen", "user": PLUGIN_CFG["panorama_user"], "password": PLUGIN_CFG["panorama_password"]}

    response = requests.get(f"https://{url}/api/", params=params, verify=False)
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


def compare_address_objects(address_objects, connection):
    results = []
    for addr in address_objects:
        # Set initial values to be used in final results (row)
        loop_result = [addr, "address"]

        # Parse out the IP address and CIDR
        oct1, oct2, oct3, oct4, cidr = addr.split("_")[1:]
        ip_address = f"{oct1}.{oct2}.{oct3}.{oct4}/{cidr}"

        # Build Panos Objects to attempt to compare to.
        addr_obj = AddressObject(name=addr, value=ip_address)
        panos_obj = connection.add(addr_obj)

        # Catch exception if object doesn't already exist to prevent invalid comparison
        try:
            panos_obj.refresh()
        except PanObjectMissing:
            loop_result.append("Does not exist")
            results.append(loop_result)
            continue

        if panos_obj.value != ip_address:
            loop_result.append(f"Descrepency!! Nautobot value: {ip_address}, Panorama value: {panos_obj.value}")
        else:
            loop_result.append(f"Nautobot and Panorama are in sync for {addr}.")

        results.append(loop_result)

    return results


def compare_service_objects(service_objects, connection):
    results = []
    for svc in service_objects:
        # Set initial values to be used in final results (row)
        loop_result = [svc, "service"]

        # Parse out the IP address and CIDR
        protocol, port = svc.split("_")[1:]

        # Build Panos Objects to attempt to compare to.
        svc_obj = ServiceObject(name=svc, protocol=protocol, destination_port=port)
        panos_obj = connection.add(svc_obj)

        # Catch exception if object doesn't already exist to prevent invalid comparison
        try:
            panos_obj.refresh()
        except PanObjectMissing:
            loop_result.append("Does not exist")
            results.append(loop_result)
            continue

        status_msg = ""
        if panos_obj.protocol != protocol:
            status_msg += f"Nautobot protocol: {protocol}, Panorama protocol: {panos_obj.protocol}"
        if panos_obj.destination_port != port:
            status_msg += f" Nautobot port: {port}, Panorama port: {panos_obj.destination_port}"

        if not status_msg:
            loop_result.append(f"Nautobot and Panorama are in sync for {svc}.")
        else:
            loop_result.append(status_msg)

        results.append(loop_result)

    return results

def parse_all_rule_names(xml_rules: str) -> list:
    rule_names = []
    root = ET.fromstring(xml_rules)
    # Get names of rules
    for i in root.findall('.//entry'):
        name = i.attrib.get("name")
        rule_names.append(name)
    return rule_names