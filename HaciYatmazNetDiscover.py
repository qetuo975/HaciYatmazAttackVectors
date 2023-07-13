import scapy.all as sc


arp_header = sc.ARP(pdst="192.168.1.1/24")
ether_header = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
arp_request_packet = ether_header / arp_header
answered_list = sc.srp(arp_request_packet, timeout=1)[0]

clients_list = []

for elements in answered_list:
    client_dict = {"ip": elements[1].psrc, "mac": elements[1].hwsrc}
    clients_list.append(client_dict)

print(str(clients_list))