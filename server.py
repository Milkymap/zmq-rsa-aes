import os 
import zmq 
import click
import json, pickle  
import time 

import operator as op 
import numpy as np 

import hashlib

from glob import glob 
from time import time, sleep  
from loguru import logger


from base64 import b64encode, b64decode
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA 
from Crypto.Cipher import AES, PKCS1_OAEP

class ZMQServer:
    TXT = b'txt'
    IMG = b'img'
    SND = b'snd'
    FLE = b'fle'
    VID = b'vid'

    ERR = b'err'
    HSK = b'hsk'
    STS = b'sts'

    BEG = b'beg'
    END = b'end'

    DLM = b''
    LNK = b'lnk'

    BYT = b'byt'
    JSN = b'jsn'
    PKL = b'pkl'

    EXT = b'ext'

    def __init__(self, server_port, path2databse):
        self.rate = 0.3
        self.server_port = server_port 

        self.ctx = zmq.Context()
        self.router = self.ctx.socket(zmq.ROUTER)
        self.router_ctl = zmq.Poller()

        self.router.bind(f'tcp://*:{server_port}')
        self.router_ctl.register(self.router, zmq.POLLIN)

        self.path2database = path2databse
        self.memory_map = {}
        self.connected_clients = {}  # pseudo to addr

        if os.path.isfile(self.path2database) and os.path.getsize(self.path2database) > 0:
            logger.debug(f'load database from {self.path2database}')
            with open(self.path2database, 'r', encoding='utf-8') as fp:
                stored_data = json.load(fp)
                self.memory_map = stored_data
    
    def make_aes_256_key(self):
        return get_random_bytes(32)

    def rsa_encryption(self, rsa_pubkey, encoded_data):
        rsa_pem_pubkey = b64decode(rsa_pubkey.encode('utf-8'))
        rsa_real_pubkey = PKCS1_OAEP.new(RSA.import_key(rsa_pem_pubkey))
        encrypted_data = rsa_real_pubkey.encrypt(encoded_data)
        return encrypted_data
    
    def toB64(self, data):
        return b64encode(data).decode('utf-8')

    def generate_salt(self):
        return get_random_bytes(16)

    def deserialize(self, serializer_type, encoded_data):
        if serializer_type == ZMQServer.JSN:
            return json.loads(encoded_data.decode())
        if serializer_type == ZMQServer.PKL:
            return pickle.loads(encoded_data)
        if serializer_type == ZMQServer.BYT:
            return encoded_data.decode()
    
    def perform_hsk(self, client_addr, decoded_data):
        keys = ('pseudo', 'rsa_pubkey', 'password', 'connection_type')
        pseudo, rsa_pubkey, password, connection_type = op.itemgetter(*keys)(decoded_data)
        if connection_type == 'SIGNIN':
            if pseudo in self.memory_map:
                decoded_salt = self.memory_map[pseudo]['salt']
                joined_salt_password = ''.join([decoded_salt, password]).encode('utf-8')
                hashed_password = hashlib.sha256(joined_salt_password).hexdigest()
                if hashed_password == self.memory_map[pseudo]['hashed_password']:
                    self.connected_clients[pseudo] = client_addr
                    return {'status': 1, 'message': 'handshake was performed...!'}
            return {'status': 0, 'message': 'your password is not valid'}
        if connection_type == 'SIGNUP':
            if pseudo in self.memory_map:
                return {'status': 0, 'message': 'impossible to signup'}
            generated_salt = self.generate_salt()
            encoded_salt = b64encode(generated_salt).decode('utf-8')
            joined_salt_password = ''.join([encoded_salt, password]).encode('utf-8')
            hashed_password = hashlib.sha256(joined_salt_password).hexdigest()

            self.memory_map[pseudo] = { 
                'salt': encoded_salt,
                'hashed_password': hashed_password,
                'rsa_pubkey': rsa_pubkey
            }
            with open(self.path2database, 'w', encoding='utf-8') as fp:
                json.dump(self.memory_map, fp)     
                return {'status': 1, 'message': 'signup was performed successfully'}

    def start(self):
        try:
            limit = 1
            marker_0 = time()
            keep_loop = True 
            while keep_loop:
                marker_1 = time()
                duration = marker_1 - marker_0
                if duration > limit:
                    logger.debug(f'server is running at port {self.server_port}')
                    marker_0 = marker_1

                incoming_events = dict(self.router_ctl.poll(10))
                if self.router in incoming_events:
                    if incoming_events[self.router] == zmq.POLLIN:
                        incoming_data = self.router.recv_multipart()
                        client_addr, _, action_type, _, serializer_type, _, encoded_data = incoming_data
                        decoded_data = self.deserialize(serializer_type, encoded_data)
                        if action_type == ZMQServer.HSK:
                            response = self.perform_hsk(client_addr, decoded_data)
                            self.router.send_multipart([client_addr, ZMQServer.DLM, ZMQServer.HSK, ZMQServer.DLM, ZMQServer.JSN, ZMQServer.DLM], flags=zmq.SNDMORE)
                            self.router.send_json(response)
                            if response['status'] == 1:
                                logger.success('server perform handshake successfully')
                            else:
                                logger.warning('server falied to perform handshake')
                        
                        if action_type == ZMQServer.EXT:
                            decoded_pseudo = self.deserialize(serializer_type, encoded_data)
                            logger.debug(f'{decoded_pseudo} want to exit')
                            if decoded_pseudo in self.connected_clients:
                                del self.connected_clients[decoded_pseudo]
                        
                        if action_type == ZMQServer.STS:
                            pseudo_array = list(self.memory_map.keys())
                            response = json.dumps({
                                'contacts': pseudo_array,
                                'conencted': list(self.connected_clients.keys())
                            }).encode()
                            self.router.send_multipart([
                                client_addr, 
                                ZMQServer.DLM,
                                ZMQServer.STS, 
                                ZMQServer.DLM,
                                ZMQServer.JSN, 
                                ZMQServer.DLM,
                                response 
                            ])
                        
                        if action_type == ZMQServer.LNK:
                            decoded_data = self.deserialize(serializer_type, encoded_data)
                            if decoded_data['type'] == 'request':
                                if decoded_data['target'] in self.connected_clients:
                                    data2send = {
                                        'type': 'question', 
                                        'contents': 'canal?',
                                        'source': decoded_data['source']
                                    }
                                    self.router.send_multipart([
                                        self.connected_clients[decoded_data['target']], 
                                        ZMQServer.DLM,
                                        ZMQServer.LNK, 
                                        ZMQServer.DLM,
                                        ZMQServer.JSN, 
                                        ZMQServer.DLM,
                                        json.dumps(data2send).encode()
                                    ])
                            
                            if decoded_data['type'] == 'response':
                                if decoded_data['contents'] == 'oui':
                                    random_key = get_random_bytes(32)  
                                    logger.success('AES key was created')

                                    source_pub_key = self.memory_map[decoded_data['source']]['rsa_pubkey']
                                    target_pub_key = self.memory_map[decoded_data['target']]['rsa_pubkey']

                                    source_cipher_key = self.rsa_encryption(source_pub_key, random_key)
                                    target_cipher_key = self.rsa_encryption(target_pub_key, random_key)
                                    
                                    source_cipher_key = self.toB64(source_cipher_key)
                                    target_cipher_key = self.toB64(target_cipher_key)
                                    logger.success('AES key was encrypted for both clients')

                                    data2send_source = {
                                        'type': 'response',
                                        'target': decoded_data['target'],
                                        'key': source_cipher_key
                                    }


                                    data2send_target = {
                                        'type': 'response',
                                        'target': decoded_data['source'],
                                        'key': target_cipher_key
                                    }
                                    self.router.send_multipart([
                                        self.connected_clients[decoded_data['source']],
                                        ZMQServer.DLM,
                                        ZMQServer.LNK, 
                                        ZMQServer.DLM,
                                        ZMQServer.JSN, 
                                        ZMQServer.DLM,
                                        json.dumps(data2send_source).encode()
                                    ])

                                    self.router.send_multipart([
                                        self.connected_clients[decoded_data['target']],
                                        ZMQServer.DLM,
                                        ZMQServer.LNK, 
                                        ZMQServer.DLM,
                                        ZMQServer.JSN, 
                                        ZMQServer.DLM,
                                        json.dumps(data2send_target).encode()
                                    ])

                # end if ...! 
            # end loop ...! 

        except KeyboardInterrupt as e:
            pass 
        except Exception as e:
            logger.error(e)
        finally:
            logger.debug('server waits for remote client to disconnect')
            sleep(1)
            self.router_ctl.unregister(self.router)
            self.router.close()
            self.ctx.term()

@click.command()
@click.option('-sp', '--server_port', help='port of the server', type=int)
@click.option('-pd', '--path2database', type=click.Path(False))
def entrypoint(server_port, path2database):
    server = ZMQServer(server_port, path2database)
    server.start()

if __name__ == '__main__':
    entrypoint()