#!/usr/bin/env python

import scapy.all as scapy
import argparse

print("---------Welcome To Network Scanner----------")

def scan_parse():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Enter Target IP to use Network Scanner")
    values = parser.parse_args()
    if not values.target:
        parser.error("[-]Please Specify the Target, use --help for more info")
    return values

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broad = broadcast/arp_request
    answered_list = scapy.srp(arp_broad, timeout=1, verbose=False)[0]
    client_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)
    return client_list

def result(result_list):
    print("IP Address\t\t\tMAC Address\n---------------------------------------------------")
    for client in result_list:
        print(client["ip"] + "\t\t\t" + client["mac"])

    # print(element[1].psrc + "\t\t" + element[1].hwsrc)
    # print(answered_list.summary())
    # print(unanswered_list.summary())
    # print(arp_broad.summary())
    # arp_broad.show()
    # arp_request.show()
    # broadcast.show()
    # print(broadcast.summary())
    # print(arp_request.summary())
    # scapy.ls(scapy.ARP())
    # scapy.ls(scapy.Ether())

values = scan_parse()
scan_result = scan(values.target)
result(scan_result)

print("-------ENJOY HACKING---------")


