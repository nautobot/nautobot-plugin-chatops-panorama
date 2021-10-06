from nautobot_plugin_chatops_panorama.constant import PLUGIN_CFG

from panos.panorama import DeviceGroup, Panorama
from panos.firewall import Firewall
from panos.objects import AddressObject, ServiceObject
from panos.errors import PanObjectMissing, PanDeviceXapiError
from requests.exceptions import RequestException
import defusedxml.ElementTree as ET
import requests
from netmiko import ConnectHandler
import time
from panos.policies import Rulebase, SecurityRule


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


def get_rule_match(connection: Panorama, five_tuple: dict, serial: str) -> dict:
    """Method to obtain the devices connected to Panorama.
    Args:
        connection (Panorama): Connection object to Panorama.
    Returns:
        dict: Dictionary of all devices attached to Panorama.
    """

    host = PLUGIN_CFG["panorama_host"].rstrip("/")
    fw = Firewall(serial=serial)
    pano = Panorama(host, api_key=get_api_key_api())
    pano.add(fw)
    return fw.test_security_policy_match(
        source=five_tuple["src_ip"],
        destination=five_tuple["dst_ip"],
        protocol=int(five_tuple["protocol"]),
        port=int(five_tuple["dst_port"]),
    )


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


def start_packet_capture(ip: str, filters: dict):
    """Starts or stops packet capturing on the Managed FW.

    Args:
        ip (str): IP address of the device
        filters (dict): Commands to pass to the device for packet capturing

    """

    dev_connect = {
        "device_type": "paloalto_panos",
        "host": ip,
        "username": PLUGIN_CFG["panorama_user"],
        "password": PLUGIN_CFG["panorama_password"],
    }

    command = f"debug dataplane packet-diag set filter index 1 match ingress-interface {filters['intf_name']}"

    if filters["dport"]:
        command += f" destination-port {filters['dport']}"

    if filters["dnet"] != "0.0.0.0":
        command += f" destination {filters['dnet']}"
        if filters["dcidr"] != "0":
            command += f" destination-netmask {filters['dcidr']}"

    if filters["snet"] != "0.0.0.0":
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
    _get_pcap(ip)


def _get_pcap(ip: str):
    """Downloads PCAP file from PANOS device

    Args:b
        ip (str): IP address of the device
    """

    url = f"https://{ip}/api/"

    params = {"key": get_api_key_api(), "type": "export", "category": "filters-pcap", "from": "1.pcap"}

    respone = requests.get(url, params=params, verify=False)

    with open("captured.pcap", "wb") as pcap_file:
        pcap_file.write(respone.content)


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
            loop_result.append(f"Discrepancy!! Nautobot value: {ip_address}, Panorama value: {panos_obj.value}")
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
        protocol = protocol.lower()

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
            status_msg += f"Incorrect protocol: ({protocol}/{panos_obj.protocol})"
        if panos_obj.destination_port != port:
            status_msg += f"Incorrect port: ({port}/{panos_obj.destination_port})"

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
    for i in root.findall(".//entry"):
        name = i.attrib.get("name")
        rule_names.append(name)
    return rule_names


def get_all_rules(device=None):
    pano = connect_panorama()
    devices = pano.refresh_devices(expand_vsys=False, include_device_groups=False)
    device = pano.add(devices[0])
    # TODO: Future - filter by name input, the query/filter in Nautobot DB and/or Panorama
    # if not device:
    #     devices = pano.refresh_devices(expand_vsys=False, include_device_groups=False)
    #     device = pano.add(devices[0])
    rulebase = device.add(Rulebase())
    rules = SecurityRule.refreshall(rulebase)
    return rules


def split_rules(rules, title=""):
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


def register_device(serials, group) -> str:
    """Registers device with Panorama to a new or existing device group by its serial number.

    Args:
        serials (str): Comma separated device serial numbers
        group (str): Existing group name on Panorama

    Returns:
        (str): Returns message about the performed job.
    """
    pano_obj = connect_panorama()
    for serial in serials.split(","):
        fw = Firewall(serial=serial)
        pano_obj.add(fw).create()

        if group != "None":
            groups = pano_obj.refresh_devices()

            group_present = False
            for group_obj in groups:
                if group == group_obj.name:
                    group_present = True
                    group = group_obj

            # Create DeviceGroup in Panorama if does not exist
            if not group_present:
                group = DeviceGroup(group)
                pano_obj.add(group).create()

            for device_obj in group.children:
                if serial == device_obj.serial:
                    return f"Device with serial number `{serial}` is already registered with `{group.name}`."

            try:
                group.add(fw).create()
                return f"Device with serial number '{serial}' was successfully registered with `{group.name}`."
            except PanDeviceXapiError:
                return f"Something went wrong while adding device to the `{group.name}` group. It is possible that this device is already registered with a different group."
        else:
            return f"Device with serial number `{serial}` was successfully registered with Panorama."
