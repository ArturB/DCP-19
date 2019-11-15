import argparse
import bz2
from netfilterqueue import NetfilterQueue
from scapy.layers.inet import TCP, IP
import hashlib
import os
from collections import deque
from enum import Enum

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send

from netfilterqueue import NetfilterQueue


class ClientState(Enum):
    LISTEN = 0
    KEY_RECEIVED = 1
    DATA_RECEIVING = 2
    FIN_RECEIVED = 3
    CLOSING = 4
    CLOSED = 5


class Flag(Enum):
    NONE = 0
    KEY = 1
    FIN = 2
    RET = 4
    FIN_ACK = 8

from scapy.sendrecv import send


class client:
    def __init__(self, file_name, src, dst, scr_port, dst_port):
        self.file_name = file_name
        self.file_list = []
        self.my_private_key, self.my_public_key = self.load_keys()
        self.server_public_key = None
        self.send_queue = deque()
        self.state = ClientState.LISTEN
        self.session_id = 0
        self.dst_port = dst_port
        self.scr_port = scr_port
        self.dst = dst
        self.src = src
        self.tmp_count = 0

    def load_keys(self):
        # TODO GENERATE SS: PAIRS USING from Crypto.PublicKey import RSA
        key = RSA.generate(2048)
        return key, key.publickey()
    
    def start_netfilter(self):
        packets_queue = NetfilterQueue()
        packets_queue.bind(2, self.packet_callback)
        try:
            packets_queue.run()
        except KeyboardInterrupt:
            print('')
        packets_queue.unbind()

    def get_outcoming_packet(self, load_len):
        load_array = bytearray(os.urandom(load_len))
        load_array = self.generate_packet(load_array, self.send_queue.popleft())
        return load_array

    def packet_callback(self, _packet):
        tcp_packet = TCP(_packet.get_payload())
        
        if self.is_hash_valid(tcp_packet.load):
            print("Get stegano packet")
            if self.state == ClientState.LISTEN:    
                self.session_id, sequence_id, flag, data_size, data = self.get_packet_data(tcp_packet.load)
                if flag == Flag.KEY.value:
                    self.server_public_key = RSA.importKey(data)
                    # Prepare packet for sending client public key
                    tcp_packet = self.generate_header(self.session_id, 4294967295, Flag.KEY.value, self.my_public_key.exportKey())
                    self.send_queue.append(tcp_packet)
                    self.state = ClientState.KEY_RECEIVED
                    load_array = self.get_outcoming_packet(1460)
                    self.send_to_server(load_array)
                    self.state = ClientState.DATA_RECEIVING

            elif self.state == ClientState.DATA_RECEIVING:
                decrypted_load = self.decrypt_data(tcp_packet.load)
                session_id, sequence_id, flag, data_size, data = self.get_packet_data(decrypted_load)
                
                if flag == Flag.NONE.value and self.session_id == session_id:
                    self.file_list.append((sequence_id, data))
                elif flag == Flag.FIN.value and self.session_id == session_id:
                    self.file_list.append((sequence_id, data))
                    self.state = ClientState.FIN_RECEIVED
                    to_resend_list = self.create_file(sequence_id)
                    if len(to_resend_list) == 0:
                        tcp_packet = self.generate_header(self.session_id, 4294967295, Flag.FIN.value, os.urandom(50))
                        encrypted_data = self.encrypt(tcp_packet)
                        self.send_queue.append(encrypted_data)
                        load_array = self.get_outcoming_packet(1460)
                        self.send_to_server(load_array)
                        self.state = ClientState.CLOSING

            elif self.state == ClientState.CLOSING:
                decrypted_load = self.decrypt_data(tcp_packet.load)
                session_id, sequence_id, flag, data_size, data = self.get_packet_data(decrypted_load)
                if flag == Flag.FIN_ACK.value and self.session_id == session_id: 
                    self.state = ClientState.CLOSED

        _packet.accept()

    def encrypt(self, to_encrypt):
        if len(to_encrypt) < 1070:
            to_encrypt = to_encrypt + os.urandom(1070-len(to_encrypt))
        chunk_size = int(len(to_encrypt)/5)
        data_splited = [to_encrypt[0+i:chunk_size+i] for i in range(0, len(to_encrypt), chunk_size)]
        data_encrypted_list = []
        cipher = PKCS1_OAEP.new(self.server_public_key)
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

    def create_file(self, chunk_amount):
        sorted_list = sorted(self.file_list, key=lambda x: x[0])
        with open(self.file_name, 'ab') as txt_file:
            for batch in sorted_list:
                txt_file.write(batch[1])

        with open(self.file_name, 'rb') as txt_file:
            txt_file = txt_file.read()
            decompressed_file = bz2.decompress(txt_file)

        with open(self.file_name, 'wb') as txt_file:
            txt_file.write(decompressed_file)
        return []

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

    def is_hash_valid(self, load_array):
        hash_data = hashlib.sha256(bytes(load_array[32:]))
        hash_bytes = bytearray(hash_data.digest())

        check_hash = bytearray(load_array[:32])
        return hash_bytes == check_hash
    
    def get_packet_data(self, load_array):
        session_id = int.from_bytes(load_array[32:36], byteorder='big')
        sequence_id = int.from_bytes(load_array[36:40], byteorder='big')
        flag = int(load_array[40])
        data_size = int.from_bytes(load_array[41:43], byteorder='big')
        data = load_array[43:data_size+43]
        return session_id, sequence_id, flag, data_size, data

    def payload_received(self, load):
        pass

    def send_to_server(self, payload_str):
        packet = IP(dst=self.dst, src=self.src) / TCP(sport=int(self.scr_port), dport=int(self.dst_port), seq=17459) / bytes(payload_str)
        send(packet)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", required=True)
    parser.add_argument("--sport", required=True)
    parser.add_argument("--dst", required=True)
    parser.add_argument("--dport", required=True)
    return parser.parse_args()

    def send_to_server(self, payload_str):
        packet = IP(dst=self.dst, src=self.src) / TCP(sport=self.scr_port, dport=self.dst_port, seq=17459) / payload_str
        send(packet)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", required=True)
    parser.add_argument("--sport", required=True)
    parser.add_argument("--dst", required=True)
    parser.add_argument("--dport", required=True)
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    try:
        clt = client('antygona.txt', args.src, args.dst, args.sport, args.dport)
        clt.start_netfilter()
    except Exception as err:
        print(err)
