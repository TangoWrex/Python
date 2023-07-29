#!/user/bin/env python3

import logging
from datetime import datetime
import subprocess
import os
import sys
import socket
import time
import scapy.all as scapy  # MTT

# suppress warnings to avoid them appearing in scripts
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

# preferred way to import scapy into code.
try:
    from scapy.all import *
except ImportError:
    print("Scapy package for Python not installed.")
    sys.exit()


# Get the host's Network Interface


def get_net_iface():  # MTT
    # get interface from user using scapy
    error_msg = "Invalid selection. Try again.\n"
    interfaces = get_if_list()
    # print(interfaces)
    i = 1
    for face in interfaces:
        print(f'{i}. {face}')
        i += 1
    while (True):
        user_selection = input("select your interface: ")
        if user_selection.isdigit():
            if int(user_selection) in range(len(interfaces) + 1):
                break
            else:
                print(error_msg)
        else:
            print(error_msg)
    return interfaces[int(user_selection)-1]


def enable_promiscuous(interface):  # MTT
    """
    Sets the given network interface to promiscuous mode
    """
    try:
        cmd = ["ip", "link", "set", interface, "promisc", "on"]
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        proc.communicate()
    except subprocess.CalledProcessError:
        print(f"\nFailed to configure {interface} as promiscuous.\n")
        sys.exit()
    else:
        # Executed if the try clause doesn't raise an exception
        print(f"\n{interface} was set to PROMISC mode.\n")

    # Allow user to select Sniffer parameters for sniffer


def setup_sniffer():  # MTT
    # rewrite without string concatination and proper error handling for input
    while(True):
        num_pkts = input("* Enter the number of packets to \
                    capture (0 is infinity): ")
        if num_pkts.isnumeric():
            if int(num_pkts) > 0:
                print(f'\n The program will capture {num_pkts} packets.\n')
            elif int(num_pkts) == 0:
                print("\nThe program will capture packets until the timeout\
                    expires.")
            time_to_sniff = input(
                "* Enter the number of seconds to run the capture: ")
            # Handling the value entered by the user
            if int(time_to_sniff) > 0:
                print(f"\n The program will capture packets for \
                        {time_to_sniff} seconds.\n")
            else:
                print("\nFailed. Enter a positive number of seconds")
            return num_pkts, time_to_sniff
        else:
            print("enter valid input\n")


"""
Allow the user to choose the protocol and filter by:
   0-all, 1-icmp, 2-TCP")
"""


def select_protocols():
    # include proper error handling
    protocols = ["0", "icmp", "tcp", "arp"]
    choice = int(input("Choose protocol (0-All, 1-icmp, 2-tcp, 3-arp): "))
    print(f"Sniffing: {protocols[choice]}")
    proto_sniff = protocols[choice]
    return proto_sniff


"""
Include the following for ARP and ICMP: a. timestamp, b. protocol,
c. destination Mac and IP addresses, d. source MAC and IP addresses, e. TTL
"""


def packet_log(packet):
    now = time.time()  # datetime.now()  #Get current timestamp
    try:
        print(
            f'{now} \t {packet[0].name} \t {packet[0].src} \t\
                {packet[0].dst} \t {packet[1].src} \t {packet[1].dst}\
                    \t {packet[1].ttl} \t {packet[1].dport}')
    except AttributeError:
        print(f'attribute error')


def test_proto_choice(proto_sniff):
    # fix formatting to use f'' and improve elif logic
    print(f'proto_sniff: {proto_sniff}')
    print("*\n Checking Protocol Choice...")
    print("*\n Starting the capture...")
    if proto_sniff == "0":
        filter1 = None
        # print(f'{time} ')
        print(" Time:\t\t\tProto \t\t  Source MAC \t\t Dest MAC ")
    # Added dport
    elif proto_sniff in ["tcp", "icmp"]:
        filter1 = proto_sniff
        print("Time\t\t\t  Proto \t\tSource MAC \t\t  Dest MAC \t\t \
            Source IP\t\t Dest IP \t\t TTL\t\t Port")
    # Added for ARP
    elif proto_sniff in ["arp"]:
        filter1 = proto_sniff
        print("Time:\t\t\tProto   Source MAC\t\t Dest MAC\t\t Source IP\
            \t\t OP")
    else:
        print(f'{proto_sniff} is not supported by this program.')
        sys.exit()
    return filter1


if __name__ == '__main__':
    net_iface = get_net_iface()
    print("Host's NW Intf: ", net_iface)
    # sys.exit()
    enable_promiscuous(net_iface)
    num_pkts, run_time = setup_sniffer()
    proto_sniff = select_protocols()
    filter1 = test_proto_choice(proto_sniff)
    sniff(iface=net_iface, count=int(num_pkts), filter=filter1,
          timeout=int(run_time), prn=packet_log)
