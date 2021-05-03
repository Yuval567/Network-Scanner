#########################
#    Network Scanner    #
#    By: Yuval Cohen    #
#    Date: 4.4.20       #
#########################

import socket
import threading
from scapy.all import *


def check_ip(ip):
    """
    The function builds a ARP packet and send it to the ip.
    If the packet received successfully it will be added to the ip list.
    :param ip: The ip address.
    """
    global ip_lst

    request = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip)
    response, _ = srp(request, timeout=1, retry=2, verbose=False)
    results = ()
    for _, packet in response:
        results = (packet.psrc, packet.hwsrc)

    if results:
        ip_lst.append(results)


def main():
    global ip_lst
    local_ip = socket.gethostbyname(socket.gethostname())
    local_ip = local_ip[:local_ip.rfind(".")]

    ip_lst = []
    print("-" * 35)
    print("      Starting the scan...")
    print("-" * 35 + "\n")

    for i in range(255):
        threading.Thread(target=check_ip, args=(f"{local_ip}.{i}",)).start()

    while threading.activeCount() > 1:
        pass

    for addr in ip_lst:
        print(f"Ip address: {addr[0]} | MAC address: {addr[1]}")

    input("\n\nPress any key to continue...")


if __name__ == '__main__':
    main()
