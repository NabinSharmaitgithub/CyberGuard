from scapy.all import ARP, Ether, srp
import netifaces

def get_active_hosts(interface):
    try:
        if interface not in netifaces.interfaces():
            return None, f"Interface {interface} not found."

        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET not in addrs:
            return None, f"Interface {interface} has no IPv4 address."

        ip_info = addrs[netifaces.AF_INET][0]
        ip_address = ip_info['addr']
        netmask = ip_info['netmask']

        # Create network range
        ip_range = f"{ip_address}/{netmask}"

        # Create ARP request packet
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        # Send and receive packets
        result = srp(packet, timeout=3, verbose=0)[0]

        # List of active hosts
        hosts = []
        for sent, received in result:
            hosts.append({'ip': received.psrc, 'mac': received.hwsrc})

        return hosts, None
    except Exception as e:
        return None, str(e)

def get_interfaces():
    return netifaces.interfaces()
