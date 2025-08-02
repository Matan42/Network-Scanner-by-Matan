import socket
import netifaces
import scapy.all as scapy
import json
import os

devices = []

# Global constant for harmful ports
HARMFUL_PORTS = [20, 21, 23, 137, 138, 139, 445, 3389]

def is_port_open(ip, port):
    """
    Check if a given TCP port is open on a target IP

    function gets: ip (str), port (int)
    function returns: True if port is open, False otherwise
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.1)
            s.connect((ip, port))
        return True
    except:
        return False

def create_dict(name, harmful_ports, ip, mac_address):
    """
    Create a dictionary representing a device

    function gets: name (str), harmful_ports (list), ip (str), mac_address (str)
    function returns: dictionary with device info
    """
    return {
        "name": name,
        "ip": ip,
        "mac": mac_address,
        "ports": harmful_ports
    }

def is_port_harmful(port):
    """
    Check if a port is known to be potentially dangerous

    function gets: port (int)
    function returns: True if port is in the harmful list, False otherwise
    """
    return port in [20, 21, 23, 137, 138, 139, 445, 3389]

def show_devices():
    """
    Display all scanned devices and warn about harmful ports

    function gets: none
    function returns: none
    """
    for device in devices:
        print(device['name'] + " " + device['ip'] + " " + device['mac'])
        if device['ports']:
            print("Device " + device['name'] + " might be harmful")
            port_explanation(device)

def port_explanation(device):
    """
    Explain why certain ports are considered dangerous

    function gets: device (dict)
    function returns: none
    """
    for port in device['ports']:
        if port == 20:
            print("Port 20 FTP data transfer unencrypted")
        elif port == 21:
            print("Port 21 FTP control vulnerable to brute-force")
        elif port == 23:
            print("Port 23 Telnet unencrypted remote access")
        elif port == 137:
            print("Port 137 NetBIOS Name Service exposes internal info")
        elif port == 138:
            print("Port 138 NetBIOS Datagram Service can leak data")
        elif port == 139:
            print("Port 139 NetBIOS Session Service unauthorized file access")
        elif port == 445:
            print("Port 445 SMB protocol used in ransomware attacks")
        elif port == 3389:
            print("Port 3389 RDP used in remote desktop exploits")

def get_subnet_mask_ip_mac():
    """
    Get the IP address subnet mask and MAC address of the first valid physical interface

    function gets: none
    function returns: dictionary with interface ip_address netmask mac_address or None
    """
    virtual_keywords = ['virtual', 'vmnet', 'docker', 'vbox', 'loopback', 'lo']
    for iface in netifaces.interfaces():
        if any(k in iface.lower() for k in virtual_keywords):
            continue

        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET not in addrs or netifaces.AF_LINK not in addrs:
            continue

        ip_info = addrs[netifaces.AF_INET][0]
        mac_info = addrs[netifaces.AF_LINK][0]

        ip = ip_info.get('addr')
        netmask = ip_info.get('netmask')
        mac = mac_info.get('addr')

        if ip and not ip.startswith('127') and mac and mac != "00:00:00:00:00:00" and not mac.lower().startswith("0a:00:27"):
            return {'interface': iface, 'ip_address': ip, 'netmask': netmask, 'mac_address': mac}
    return None

def check_arp_spoofing():
    """
    Detect if there is ARP spoofing on the network by checking for duplicate MACs

    function gets: none
    function returns: True if spoofing detected False otherwise
    """
    mac_to_ip = {}
    found_spoof = False
    for device in devices:
        mac = device['mac']
        ip = device['ip']
        if mac in mac_to_ip and mac_to_ip[mac] != ip:
            print("ARP Spoofing detected")
            print("MAC " + mac + " used by multiple IPs " + mac_to_ip[mac] + " and " + ip)
            found_spoof = True
        else:
            mac_to_ip[mac] = ip
    if not found_spoof:
        print("No ARP spoofing detected")
    return found_spoof

def scan():
    """
    Add the current user's device to the devices list

    function gets: none
    function returns: none
    """
    print("Scanning")
    user_info = get_subnet_mask_ip_mac()
    if user_info:
        user_device = create_dict("You", [], user_info['ip_address'], user_info['mac_address'])
        devices.append(user_device)
    else:
        print("no valid interface found")

def get_devices(ip_range):
    """
    Scan the network using ARP and check for open harmful ports

    function gets: ip_range (str)
    function returns: none
    """
    request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    request_broadcast = broadcast / request
    answered = scapy.srp(request_broadcast, timeout=1, verbose=0)[0]

    for _, response in answered:
        ip = response.psrc
        mac = response.hwsrc
        open_ports = []
        for port in HARMFUL_PORTS:
            if is_port_open(ip, port):
                open_ports.append(port)
        hostname = get_hostname(ip)
        devices.append(create_dict(hostname, open_ports, ip, mac))

def get_hostname(ip):
    """
    Get the hostname of a device by IP

    function gets: ip (str)
    function returns: hostname (str) or IP if not resolvable
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return ip


def show_main_menu():
    """
    Print menu to the user and get a valid answer.
    """
    print("Hello Welcome To Matan's Network Scanner.")
    print("This program scans your device's network shows all connected devices and searches for security threats")
    return get_answer()


def get_answer():
    """
    Function ask the user what would he like to do

    Function getss: None
    Function Returns: User's choice
    """
    print("What would you like to do?")
    print("1 Start a scan")
    print("2 Read a scan from an exsiting file")
    print("3 Write current scan to a file")
    if devices:
        print("4 Show current scan")
    print("0 Exit")

    while True:
        try:
            ans = int(input("Enter your choice:"))
            if 0 <= ans <= 3 or (devices and ans == 4):
                return ans
            print("Unrecognized option")
        except ValueError:
            print("Unrecognized option")


def write_to_file(file_name):
    """
    Function Writes to file the scan results

    Function gets: A list to write to the file
    Function returns: True or False if Executed successfuly
    """
    try:
        with open(file_name, "w") as f:
            json.dump(devices, f, indent=4)
        print("Write successful")
        return True
    except Exception as e:
        print(f"An error occurred: {e}")
        return False


def read_from_file(file_name):
    """
    Function reads an older scan from a file to a list

    Function gets: File name
    Function Returns: The list with the files content
    """
    global devices

    if not os.path.exists(file_name):
        print(f"An error occurred: [Errno 2] No such file or directory: '{file_name}'")
        return []

    try:
        with open(file_name, "r") as f:
            devices.clear()
            devices.extend(json.load(f))
        print("Read successful")
    except Exception as e:
        print(f"An error occurred: {e}")
        devices.clear()

    return devices


def scanner():
    """
    Orchestrates the network scanning process, populating the global devices list.
    """
    global devices

    devices.clear()

    scan()
    info = get_subnet_mask_ip_mac()
    if info:
        subnet_prefix = info['ip_address'].rsplit('.', 1)[0]
        get_devices(f"{subnet_prefix}.1/24")


