import socket
import struct
import sys
import ipaddress
import re
from netaddr import IPNetwork

# ---------
# Colors

YELLOW = '\033[33m'
CYAN = '\033[36m'
GREEN = '\033[32m'
ORANGE = '\033[38;5;208m'
RESET = '\033[0m'

# ---------
# Functions for checking input

def is_valid_ip(ip_address):
    # Regular expression for both IPv4 and IPv6 addresses
    pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^((?:(?:[0-9a-fA-F]{1,4}:){6}|::(?:[0-9a-fA-F]{1,4}:){5}|(?:[0-9a-fA-F]{1,4})?::(?:[0-9a-fA-F]{1,4}:){4}|(?:(?:[0-9a-fA-F]{1,4}:){0,1}[0-9a-fA-F]{1,4})?::(?:[0-9a-fA-F]{1,4}:){3}|(?:(?:[0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4})?::(?:[0-9a-fA-F]{1,4}:){2}|(?:(?:[0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4})?::(?:[0-9a-fA-F]{1,4}:){1}|(?:(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4})?::|(?:(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4})?::)(?:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}|(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)))$'

    return re.match(pattern, ip_address) is not None

def is_valid_subnet(ip_subnet):
    #Regular expression for subnet or CIDR
    pattern = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})$'

    return re.match(pattern, ip_subnet) is not None

def is_ip_range(ip_range):
    #Regular expression for ip ranges
    pattern = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$'

    return re.match(pattern, ip_range) is not None


def is_valid_ip_range(ip_range):
    #split range and check if leftside and rightside are both valid IP addresses
    ip_xpanded = ip_range.split("-")
    for ip in ip_xpanded:
        if is_valid_ip(ip):
            continue
        else:
            return False
    return True

def parse_ip_range(ip_range):
    try:
        start_ip, end_ip = ip_range.split('-')
        start_address = ipaddress.IPv4Address(start_ip.strip())
        end_address = ipaddress.IPv4Address(end_ip.strip())

        if start_address > end_address:
            raise ValueError("Start IP must be less than or equal to the end IP.")

        ip_addresses = []
        current_ip = start_address

        while current_ip <= end_address:
            ip_addresses.append(str(current_ip))
            current_ip += 1

        return ip_addresses
    except (ipaddress.AddressValueError, ValueError) as e:
        print(f"Error: {e}")
        return None

def subnet_ips(subnet):
    ip_list = []
    network = ipaddress.ip_network(subnet)
    for ip in network.hosts():
        ip_list.append(str(ip))
    return ip_list

def is_private_cidr(cidr_notation):
    try:
        ip_network = ipaddress.ip_network(cidr_notation)
        return ip_network.is_private
    except ValueError:
        return False

def expand_cidr(cidr_notation):
    try:
        ip_network = ipaddress.ip_network(cidr_notation)
        return [str(ip) for ip in ip_network]
    except ValueError as e:
        print(f"Error: {e}")
        return None

def check_input(target):
    valid_targets = []

    if is_valid_ip(target):
        return [str(target)]
    
    elif is_valid_subnet(target):
        try:
            targets_subnet = subnet_ips(target)
            return targets_subnet
        except ValueError:
            return "Invalid subnet"
        
    elif is_valid_ip_range(target): #checks for valid ip range ex. "0.0.0.0-0.0.0.255"
        try:
            targets_range = parse_ip_range(target)
            return targets_range
        except socket.gaierror:
            return "Invalid range"

    elif target.endswith('.txt'):
    # Input is text file
        try:
            with open(target, 'r') as file:
                targets = file.readlines()
            for line in targets:
                line = line.strip()
                if is_valid_subnet(line): # check if file contains subnet
                    try:
                        targets_subnet = subnet_ips(line)
                        valid_targets.extend(targets_subnet) # add all ips from the subnet to valid_targets list
                    except ValueError:
                        return "Invalid subnet"
                elif is_ip_range(line):
                    if is_valid_ip_range(line): # checks if file contains ip range ex. "0.0.0.0-0.0.0.255"
                        try:
                            targets_range = parse_ip_range(line)
                            valid_targets.extend(targets_range) # add all ips from the range to valid_targets list
                        except ValueError:
                            return "Invalid range"
                else:
                    if is_valid_ip(line):
                       valid_targets.append(line)
                    else:
                        try: # check if FQDN resolves to an IP address
                            ip_fqdn = socket.gethostbyname(line)
                            valid_targets.extend(ip_fqdn)
                        except ValueError:
                            return "Invalid FQDN"
            return valid_targets
        except FileNotFoundError:
            print("File does not exist.")
            return "Invalid target"
    else:
        try: # check if FQDN resolves to an IP address
            ip_fqdn = socket.gethostbyname(target)
            return [ip_fqdn] # return as a list
        except socket.gaierror:
            return "Invalid FQDN"
            
def main():

    if len(sys.argv) != 3:
        print("Usage: python3 smbghost.py <IP/Subnet/File/FQDN> <output_file>")
        sys.exit(1)

# ---------
# Variable Definitions

#packet to send
    pkt = b'\x00\x00\x00\xc0\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x08\x00\x01\x00\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x\x00\x00\x00\x02\x00\x00\x00\x02\x02\x10\x02"\x02$\x02\x00\x03\x02\x03\x10\x03\x11\x03\x00\x00\x00\x00\x01\x00&\x00\x00\x00\x00\x00\x01\x00 \x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\n\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'
# Get the target file or IP address from command-line argument
    targets = check_input(sys.argv[1])
# Output filename
    outfile = sys.argv[2]
    vuln_ips = []


    print(YELLOW + "[*]" + CYAN + " Scanning for SMBGhost (CVE-2020-0796 - SMBv3 RCE/DOS)..." + RESET)

    for target in targets:
        for ip in IPNetwork(target):

            sock = socket.socket(socket.AF_INET)
            sock.settimeout(3)

            try:
                sock.connect(( str(ip),  445 ))
            except:
                sock.close()
                continue

            sock.send(pkt)

    
            try:
                nb, = struct.unpack(">I", sock.recv(4))
                res = sock.recv(nb)
            except socket.timeout:
                continue
            except struct.error as e:
                continue

            if res[68:70] != b"\x11\x03" or res[70:72] != b"\x02\x00":
                continue
            else:
                vuln_ips.append(str(ip))


    # write vulnerable targets to file
    if vuln_ips:
        print(YELLOW + "[*] " + ORANGE + "Vulnerable Hosts:" + RESET)
        with open(outfile, "a+") as file:
            file.write("CVE-2020-0796 SMBGhost: \n")
            for ip in vuln_ips:
                print(f"{ip} is VULNERABLE to SMBGHOST!")
                file.write(ip + "\n")
            file.write("\n")
    else:
        print(YELLOW + "[*] " + GREEN + "No vulnerable hosts." + RESET)


if __name__ == '__main__':
    main()
