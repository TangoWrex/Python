import os
import sys
from scapy.all import *
import time
import nmap3
from pkt_sniffer import get_net_iface


# Get and Return Network Interface name as string
def get_intf():
    intf = get_net_iface()
    return intf


# Sniff for targets' mac and ip addresses and offer selection to user
def choose_victim(intf):
    print("Scanning for Victims on intf: ", intf)
    choice = {}
    num = 0
    choice[num] = ''
    macs = []
    just_macs = []
    while (True):
        try:
            packets = sniff(iface=intf, filter="arp", count=8,
                            timeout=10)
            counter = 0
            # I had to use counter for index value, packet was not working MTT
            for packet in range(len(packets)):
                just_macs.append(packets[counter].hwsrc)
                macs.append(packets[counter].hwsrc)
                macs.append(packets[counter].psrc)
                counter += 1
                if packets[counter].hwsrc not in just_macs:
                    choice[num] = macs
                    num += 1
                macs = []

        except IndexError:
            pass

        if len(choice) < 1:
            print("no victims found\n")
            sys.exit()

        for key, value in choice.items():
            print(key + 1)
            for i in value:
                print("\t", i)

        try:
            while (True):
                user_selection = input("Select a victim: ")
                if user_selection == '0':
                    return sys.exit()
                elif user_selection.isdigit():
                    user_selection = int(user_selection) - 1
                    if int(user_selection) in range(len(choice)):
                        return choice[int(user_selection)]
                    else:
                        print("Invalid selection. Try again.")
        except KeyboardInterrupt:
            return sys.exit()


# Use NMAP to probe the target IP
def nmap_probe(ip):
    nmap = nmap3.Nmap()
    nmap = nmap3.NmapScanTechniques()
    results = nmap.nmap_syn_scan(ip)
    print("Port\tState")
    # starter code print statement was not functioning correctly
    for key, value in results.items():
        for port, state in value.items():
            if port == 'ports':
                for x in state:
                    for portid in x:
                        if portid == 'portid':
                            print(f'{x[portid]}\t{x["state"]}')

    return(results)


if __name__ == '__main__':
    intf = get_intf()
    victim = choose_victim(intf)
    print(victim[0])
    print(victim[1])
    results = nmap_probe(victim[1])
