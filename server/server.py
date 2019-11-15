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



def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    args = parser.parse_args()
    return args.input


class ServerState(Enum):
    READY = 0
    KEY_SENT = 1
    DATA_SENDING = 2
    FIN_SENT = 3
    CLOSING = 4
    CLOSED = 5


class Flag(Enum):
    NONE = 0
    KEY = 1
    FIN = 2
    RET = 4
    FIN_ACK = 8


class Rate(Enum):
    DCP = 1500
    ERR = 150

class server:
    def __init__(self, txt_path):
        self.txt_path = self.compress_file(txt_path)
        self.chunk_size = 1059
        self.send_mod_packet = Rate.DCP.value
        self.send_queue = deque()
        self.file_list = self.split_file()
        self.send_count = 0
        self.session_id = 0
        self.server_ip = ''
        self.client_ip = ''
        self.state = None
        self.my_private_key, self.my_public_key = self.load_keys()
        self.client_public_key = RSA._RSAobj
        self.state = self.load_key_to_queue()
        self.random_modulo = 0
        self.random_modulo_spoil = 0
        self.tmp_count = 0

    def compress_file(self, txt_path):
        with open('antygona.txt', 'rb') as data:
            bz2data = bz2.compress(data.read(), compresslevel=9)
            with open('antygona.txt.bz2', 'wb') as write_file:
                write_file.write(bz2data)
        return 'antygona.txt.bz2'

    def generate_session_id(self):
        return random.randint(0, 4294967295)

    def load_keys(self):
        key = RSA.generate(2048)
        return key, key.publickey()

    def split_file(self):
        with open(self.txt_path, 'rb') as txt_file:
            text = txt_file.read()
        return [text[i:i+self.chunk_size] for i in range(0, len(text), self.chunk_size)]
    
    def load_key_to_queue(self):
        self.session_id = self.generate_session_id()
        tmp_header = self.generate_header(self.session_id, 4294967295, Flag.KEY.value, self.my_public_key.exportKey('PEM'))
        self.send_queue.append(tmp_header)
        return ServerState.READY
    
    def start_netfilter(self):
        packets_queue = NetfilterQueue()
        packets_queue.bind(1, self.packet_callback)
        try:
            packets_queue.run()
        except KeyboardInterrupt:
            print('')
        packets_queue.unbind()

    def packet_callback(self, _packet):
        ip_packet = IP(_packet.get_payload())
        tcp_packet = TCP(_packet.get_payload())
        # check if this is a packet which we can modify
        if self.send_count % self.send_mod_packet == self.random_modulo and len(tcp_packet.load) > 1400:
            self.random_modulo = random.randint(0, self.send_mod_packet-1)
            print("Sending stegano packet...")
            # check state
            if self.state == ServerState.READY:
                load_array = bytearray(tcp_packet.load)
                load_array = self.generate_packet(load_array, self.send_queue.popleft())
                self.state = ServerState.KEY_SENT
                self.server_ip = ip_packet.src
                self.client_ip = ip_packet.dst

                tcp_packet.load = bytes(load_array)
                _packet.set_payload(bytes(tcp_packet))

            elif self.state == ServerState.DATA_SENDING:
                load_array = bytearray(tcp_packet.load)
                load_array = self.generate_packet(load_array, self.send_queue.popleft()) 
                tcp_packet.load = bytes(load_array)
                _packet.set_payload(bytes(tcp_packet))
                # If it was last send packet in the next sending send FIN KEY

                if len(self.send_queue) == 0:
                    self.state = ServerState.FIN_SENT

        elif self.send_count % Rate.ERR.value == self.random_modulo_spoil and len(tcp_packet.load) > 1400:
            self.random_modulo_spoil = random.randint(0, Rate.ERR.value - 1)
            load_array = bytearray(tcp_packet.load)
            load_array[random.randint(0, len(tcp_packet.load)-1)] = random.randint(0, 255)
            tcp_packet.load = bytes(load_array)
            _packet.set_payload(bytes(tcp_packet))

        elif ip_packet.src == self.client_ip and len(tcp_packet.load) > 50:
            if self.is_hash_valid(tcp_packet.load):
                data_packet = tcp_packet.load
                if self.state != ServerState.KEY_SENT:
                    data_packet = self.decrypt_data(tcp_packet.load)
                session_id, sequence_id, flag, data_size, data = self.get_packet_data(data_packet)
                if session_id == self.session_id:
                    if flag == Flag.KEY.value:
                        self.client_public_key = RSA.importKey(data)
                        self.state = ServerState.DATA_SENDING
                        self.send_file_to_queue()
                    elif flag == Flag.FIN.value and self.state == ServerState.FIN_SENT:
                        tmp_header = self.generate_header(self.session_id, 4294967295, Flag.FIN_ACK.value, os.urandom(10))
                        encrypted_data = self.encrypt(tmp_header)
                        self.send_queue.append(encrypted_data)
                        self.state = ServerState.CLOSING

        self.send_count += 1
        _packet.accept()

    def send_file_to_queue(self):
        for index, batch in enumerate(self.file_list):
            if index != len(self.file_list) - 1:
                tmp_header = self.generate_header(self.session_id, index, Flag.NONE.value, batch)
                encrypted_data = self.encrypt(tmp_header)
            else:
                tmp_header = self.generate_header(self.session_id, index, Flag.FIN.value, batch)
                encrypted_data = self.encrypt(tmp_header)
            self.send_queue.append(encrypted_data)
    
    def encrypt(self, to_encrypt):
        if len(to_encrypt) < 1070:
            to_encrypt = to_encrypt + os.urandom(1070-len(to_encrypt))
        chunk_size = int(len(to_encrypt)/5)
        data_splited = [to_encrypt[0+i:chunk_size+i] for i in range(0, len(to_encrypt), chunk_size)]
        data_encrypted_list = []
        cipher = PKCS1_OAEP.new(self.client_public_key)
        for data in data_splited:
            data_encrypted_list.append(cipher.encrypt(data))
        data_encrypted = b"".join(data_encrypted_list)
        
        return data_encrypted

    def decrypt_data(self, data):
        cipher_dec = PKCS1_OAEP.new(self.my_private_key)
        data_encrypted_splited = [data[32+i:32+256+i] for i in range(0, 1280, 256)]
        data_decrypted_list = []
        for data in data_encrypted_splited:
            message = cipher_dec.decrypt(data)
            data_decrypted_list.append(message)
        return data[0:32] + b"".join(data_decrypted_list)
    
    def is_hash_valid(self, load_array):
        hash_data = hashlib.sha256(bytes(load_array[32:]))
        hash_bytes = bytearray(hash_data.digest())

        check_hash = bytearray(load_array[:32])
        return hash_bytes == check_hash
    
    def generate_header(self, session_id, sequence_id, flag, data):
        """ Generating header without hashing """
        tmp_header = bytearray()
        tmp_session_id = bytearray((session_id).to_bytes(4, byteorder='big'))
        for part in tmp_session_id:
            tmp_header.append(part)
        
        tmp_sequence_id = bytearray((sequence_id).to_bytes(4, byteorder='big'))
        for part in tmp_sequence_id:
            tmp_header.append(part)
        
        tmp_header.append(flag)

        tmp_len_data = bytearray(len(data).to_bytes(2, byteorder='big'))
        for part in tmp_len_data:
            tmp_header.append(part)
        
        for char in data:
            tmp_header.append(int(char))
        return tmp_header

    def generate_packet(self, load_array, tcp_packet):
        tmp_load = load_array
        for index, byte in enumerate(tcp_packet):
            tmp_load[32+index] = byte
        # Hash
        
        hash_data = hashlib.sha256(bytes(tmp_load[32:]))
        hash_bytes = bytearray(hash_data.digest())
        for i in range(0, 32):
            tmp_load[i] = hash_bytes[i]
        return tmp_load

    def get_packet_data(self, load_array):
        session_id = int.from_bytes(load_array[32:36], byteorder='big')
        sequence_id = int.from_bytes(load_array[36:40], byteorder='big')
        flag = int(load_array[40])
        data_size = int.from_bytes(load_array[41:43], byteorder='big')
        data = load_array[43:data_size+43]
        return session_id, sequence_id, flag, data_size, data


if __name__ == '__main__':
    input_filename = parse_args()
    ser = server(input_filename)
    ser.start_netfilter()
