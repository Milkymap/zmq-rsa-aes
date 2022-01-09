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

    BYT = b'byt'
    JSN = b'jsn'
    PKL = b'pkl'

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

    def generate_salt(self):
        return get_random_bytes(16)

    def deserialize(self, serializer_type, encoded_data):
        if serializer_type == ZMQServer.JSN:
            return json.loads(encoded_data.decode())
        if serializer_type == ZMQServer.PKL:
            return pickle.loads(encoded_data)
        if serializer_type == ZMQServer.BYT:
            return encoded_data.decode()
    
    def perform_hsk(self, decoded_data):
        keys = ('pseudo', 'rsa_pubkey', 'password', 'connection_type')
        pseudo, rsa_pubkey, password, connection_type = op.itemgetter(*keys)(decoded_data)
        if connection_type == 'SIGNIN':
            if pseudo in self.memory_map:
                decoded_salt = self.memory_map[pseudo]['salt']
                joined_salt_password = ''.join([decoded_salt, password]).encode('utf-8')
                hashed_password = hashlib.sha256(joined_salt_password).hexdigest()
                if hashed_password == self.memory_map[pseudo]['hashed_password']:
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
                return {'status': 1}

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
                            response = self.perform_hsk(decoded_data)
                            self.router.send_multipart([client_addr, ZMQServer.DLM, ZMQServer.HSK, ZMQServer.DLM, ZMQServer.JSN, ZMQServer.DLM], flags=zmq.SNDMORE)
                            self.router.send_json(response)
                            if response['status'] == 1:
                                logger.success('server perform handshake successfully')
                            else:
                                logger.warning('server falied to perform handshake')
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