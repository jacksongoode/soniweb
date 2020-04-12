#! /usr/bin/env python3

import os
import time
import pyshark
import socket
import geoip2.database
import argparse
from pythonosc import udp_client
import sslkeylog

# Grab SSL Key
# sslkeylog.set_keylog(os.environ.get('SSLKEYLOGFILE'))

# Read from the Geoip2 database
reader = geoip2.database.Reader(os.path.dirname(os.path.realpath(__file__))+"/GeoLite2-City.mmdb")

# Set IP of current computer (multiple methods)
# 1 - Socket
#try:
#    host_ip = socket.gethostbyname(socket.gethostname())
#except socket.error:
#    host_ip = "192.168.1.3"
# 2 - Web lookup
#from requests import get
#host_ip = get('https://api.ipify.org').text
# 3 - Manual
host_ip = "192.168.1.3" # Please replace with your own *local* IP address

port = input("Port: ")
if port == "":
    port = 8000

pkt_len = input("Minimum size of packet: ")

print("Host IP: "+host_ip)
t = time.time()

prior_src = "0.0.0.0"
prior_dst = "0.0.0.0"
prior_len = 0

# Counting packet type
tcp_cnt = 0
udp_cnt = 0
tls_cnt = 0
dns_cnt = 0
other_cnt = 0

# Set up OSC server
parser = argparse.ArgumentParser()
parser.add_argument("--ip", default="127.0.0.1")
parser.add_argument("--port", type=int, default=port)
args = parser.parse_args()
client = udp_client.SimpleUDPClient(args.ip, args.port)

# Set up capture and filter by host IP and packet size - *specify interface*
capture = pyshark.LiveCapture(interface="en0",
                              bpf_filter="ip and host "+host_ip+" and length > "+pkt_len)

for packet in capture:
    #if "ip" in packet:
        # Prevent identical connections from happening twice
        if (prior_len != packet.length):
            #prior_src = packet.ip.src
            #prior_dst = packet.ip.dst
            prior_len = packet.length
            try:
                # Debugging
                print("[Protocol:] "+packet.highest_layer+
                    " [Source IP:] "+packet.ip.src+
                    " [Destination IP:] "+packet.ip.dst+
                    " [Size:] "+packet.length)
                
                # To OSC
                client.send_message("/packet_len", int(packet.length))
                
                if packet.highest_layer == "TLS":
                    client.send_message("/protocol", 0)
                    # tcp_cnt = tcp_cnt + 1
                elif packet.highest_layer == "TCP":
                    client.send_message("/protocol", 1)
                    # udp_cnt = udp_cnt + 1
                elif packet.highest_layer == "DNS":
                    client.send_message("/protocol", 2)
                    # tls_cnt = tls_cnt + 1
                elif packet.highest_layer == "HTML":
                    client.send_message("/protocol", 3)
                    # dns_cnt = dns_cnt + 1
                else:
                    client.send_message("/protocol", 4)
                    # other_cnt = other_cnt + 1

                # Sent
                if packet.ip.src == host_ip:
                    dst_resp = reader.city(packet.ip.dst)
                    client.send_message("/dest_name", dst_resp.country.name)
                    client.send_message("/direction", 0)
                    client.send_message("/ip_lat", round((dst_resp.location.latitude+90)/60)) # 0 to 3 (4 degrees of differentiation)
                    client.send_message("/ip_long", round((dst_resp.location.longitude+180)/51.43)) # 0 to 7 (8 degrees of differentiation)
                    
                    print("Sent to "+str(dst_resp.country.name))
                
                # Recieved
                if packet.ip.dst == host_ip:
                    src_resp = reader.city(packet.ip.src)
                    client.send_message("/source_name", src_resp.country.name)
                    client.send_message("/direction", 1)
                    client.send_message("/ip_lat", round((src_resp.location.latitude+90)/60))
                    client.send_message("/ip_long", round((src_resp.location.longitude+180)/51.43))
                    
                    print("Received from "+str(src_resp.country.name))

            # If the IP is not in the database
            except geoip2.errors.AddressNotFoundError:
                print("IP not found in the database!")
                # Testing
                # print("TCP: "+str(tcp_cnt)+" UDP: "+str(udp_cnt)+" TLS: "+str(tls_cnt)+" DNS: "+str(dns_cnt)+" Other: "+str(other_cnt))