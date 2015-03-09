# Example code showing how to create a generator that returns
# TCP packet payloads from packets captured using libpcap
#
# You may need to install these modules:
#     pip install pcap dpkt
#
# Copyright (C) 2015 Harvey Chapman <hchapman@3gfp.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

import pcap
import dpkt
import time
import binascii

DEBUG = False

def print_hex_string_nicely(hex_string):
    index = 0
    result = ''
    while hex_string:
        result += '{:08x}: '.format(index)
        index += 16
        line, hex_string = hex_string[:32], hex_string[32:]
        while line:
            two_bytes, line = line[:4], line[4:]
            if two_bytes:
                result += two_bytes + ' '
        result = result[:-1] + '\n'
    print result

def hex_dump_packet(packet_data):
    print_hex_string_nicely(binascii.hexlify(packet_data))

packet_function = None

def get_tcp_from_ethernet(data):
    packet = dpkt.ethernet.Ethernet(data)
    if isinstance(packet.data, dpkt.ip.IP):
        return packet.data.data.data
    return None

def get_tcp_from_loopback(data):
    packet = dpkt.loopback.Loopback(data)
    if isinstance(packet.data, dpkt.ip.IP):
        return packet.data.data.data
    return None

def get_tcp_from_ip(data):
    packet = dpkt.ip.IP(data)
    if isinstance(packet, dpkt.ip.IP):
        return packet.data.data
    return None

def determine_packet_function(packet_data):
    type_functions = [get_tcp_from_ethernet,
                      get_tcp_from_loopback,
                      get_tcp_from_ip]
    for fn in type_functions:
        if fn(packet_data) is not None:
            if DEBUG: print 'Packet type:', fn.__name__.split('_')[-1]
            return fn
    return None

def tcp_data_from_packet_data(packet_data):
    global packet_function
    if not packet_function:
        packet_function = determine_packet_function(packet_data)
        if not packet_function:
            return None
    return packet_function(packet_data)

def tcp_data_from_filter(filter="", interface=None):
    # interface notes:
    #     iptap and pktap alone act like ",any" is appended
    #     'any' is a synonym for 'pktap,any'
    #     pktap and iptap do not work with permiscuous mode
    #     iptap seems to take no more than 23 characters
    #     pktap only takes 8 interfaces
    #     pcap.findalldevs() will return a list of interfaces
    #     Using iptap makes coding easier since pcap will only
    #     return the IP portion of the packet
    if not interface:
        interface="iptap"
    if DEBUG: print 'Capturing on interface(s):',interface
    # You must set timeout_ms. Not sure why the default doesn't work.
    pc = pcap.pcap(name=interface,         # default: None
                   snaplen=256 * 1024,     # default: 64k, but tcpdump uses 256k
                   timeout_ms=500)         # defailt: 500, but tcpdump uses 1000
    pc.setfilter(filter)
    for capture in pc:
        if not capture:
            continue
        timestamp, packet_data = capture
        if DEBUG: hex_dump_packet(packet_data)
        tcp_data = tcp_data_from_packet_data(packet_data)
        if tcp_data is not None:
            yield timestamp, tcp_data

def timestring(timestamp):
    # 00:14:21.836925
    t = time.localtime(timestamp)
    s = '{:0.6f}'.format(timestamp - int(timestamp))[1:]
    return '{:02}:{:02}:{:02}{}'.format(t.tm_hour, t.tm_min, t.tm_sec, s)

def print_tcp_data_from_filter(**kwargs):
    for timestamp, data in tcp_data_from_filter(**kwargs):
        print "{}    {}".format(timestring(timestamp), data)

# Only show packets containing actual data, i.e. no protocol-only
# packets, coming from my server on port 9988.
filter = 'tcp src port 9988 and (tcp[tcpflags] & tcp-push != 0)'
print_tcp_data_from_filter(filter=filter)
