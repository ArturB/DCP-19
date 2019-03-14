import argparse
import bz2
import datetime
import hashlib
import os
import random
import string
import time
from collections import deque
from enum import Enum

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from scapy.all import IP
from scapy.layers.inet import TCP

from netfilterqueue import NetfilterQueue

class Rate:
    DCP = 1500
    ERR = 250

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    args = parser.parse_args()
    return args.input

###########################
## ERROR SIMULATOR CLASS ##
###########################

class server_nodcp:
    def __init__(self, txt_path):
        self.chunk_size = 1059
        self.send_mod_packet = 100
        self.send_queue = deque()
        self.send_count = 0
        self.session_id = 0
        self.server_ip = ''
        self.client_ip = ''
        self.state = None
        self.client_public_key = RSA._RSAobj
        self.random_modulo = 0
        self.random_modulo_spoil = 0
        self.tmp_count = 0
    
    def packet_callback(self, _packet):
        tcp_packet = TCP(_packet.get_payload())
        # check if this is a packet which we can modify
        if self.send_count % Rate.ERR == self.random_modulo_spoil and len(tcp_packet.load) > 1400:
            self.random_modulo_spoil = random.randint(0, Rate.ERR - 1)
            load_array = bytearray(tcp_packet.load)
            load_array[random.randint(0, len(tcp_packet.load)-1)] = random.randint(0, 255)
            tcp_packet.load = bytes(load_array)
            _packet.set_payload(bytes(tcp_packet))

        self.send_count += 1
        _packet.accept()

    def start_netfilter(self):
        packets_queue = NetfilterQueue()
        packets_queue.bind(1, self.packet_callback)
        try:
            packets_queue.run()
        except KeyboardInterrupt:
            print('')
        packets_queue.unbind()


if __name__ == '__main__':
    input_filename = parse_args()
    ser = server_nodcp(input_filename)
    ser.start_netfilter()
