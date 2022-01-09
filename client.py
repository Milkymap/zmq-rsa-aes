import os 
import cv2 
import zmq 
import click 

import json 
import pickle 

import numpy as np 
import operator as op 
import itertools as it, functools as ft 

from base64 import b64encode, b64decode

from Crypto.PublicKey import RSA 
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes


from loguru import logger 

class ZMQClient:

    TXT = b'txt'
    SND = b'snd'
    IMG = b'img'

    BYT = b'byt'
    JSN = b'jsn'
    PKL = b'pkl'

    BEG = b'beg'
    END = b'end'

    DLM = b''
    
    LNK = b'lnk'

    ERR = b'err'
    HSK = b'hsk'
    STS = b'sts'
    EXT = b'ext'

    def __init__(self, endpoint, pseudo, password, connection_type='SIGNIN', secret='secret.json'):
        self.pseudo = pseudo 
        self.password = password 
        self.endpoint = endpoint 
        self.connection_type = connection_type
        self.secret = secret
        self.canals = {}
        logger.debug('rsa key generation ...!')
        
        if os.path.isfile(self.secret) and os.path.getsize(self.secret):
            logger.debug(f'rsa key will be loaded from {self.secret}')
            with open(self.secret, 'r') as file_pointer:
                load_data = json.load(file_pointer)
                self.pem_prv_key = b64decode(load_data['pem_prv_key'].encode('utf-8'))
                self.pem_pub_key = b64decode(load_data['pem_pub_key'].encode('utf-8'))

                self.pub_key = RSA.import_key(self.pem_pub_key)
                self.prv_key = RSA.import_key(self.pem_prv_key)        
        else:
            key = RSA.generate(2048)
            self.pem_prv_key = key.export_key('PEM')
            self.pem_pub_key = key.publickey().exportKey('PEM')
        
            self.pub_key = RSA.import_key(self.pem_pub_key)
            self.prv_key = RSA.import_key(self.pem_prv_key)    

            with open(self.secret, 'w') as file_pointer:
                data = {
                    'pem_prv_key': b64encode(self.pem_prv_key).decode('utf-8'), 
                    'pem_pub_key': b64encode(self.pem_pub_key).decode('utf-8')
                }
                json.dump(data, file_pointer)
        
        self.ctx = zmq.Context()
        self.dealer = self.ctx.socket(zmq.DEALER)
        self.dealer_ctl = zmq.Poller()
        self.dealer.connect(endpoint)
        self.dealer_ctl.register(self.dealer, zmq.POLLIN)

        logger.success('zmq was initialized successfully')

        self.make_hsk()


    def rsa_encryption(self, plain):
        encryptor = PKCS1_OAEP.new(self.pub_key)
        cipher = encryptor.encrypt(plain.encode('utf-8'))
        b64_cipher = b64encode(cipher).decode('utf-8')
        return b64_cipher 

    def rsa_decryption(self, b64_cipher):
        decryptor = PKCS1_OAEP.new(self.prv_key)
        plain = decryptor.decrypt(b64decode(b64_cipher))
        return plain

    def aes_encryption(self, plain):
        pass 

    def aes_decryption(self, b64_cipher):
        pass 

    def make_hsk(self):
        message2send = {
            'pseudo': self.pseudo, 
            'password': self.password, 
            'rsa_pubkey': b64encode(self.pem_pub_key).decode('utf-8'), 
            'connection_type': self.connection_type
        }
        self.dealer.send_multipart([
                ZMQClient.DLM, 
                ZMQClient.HSK, 
                ZMQClient.DLM, 
                ZMQClient.JSN, 
                ZMQClient.DLM
            ], 
            flags=zmq.SNDMORE
        )
        self.dealer.send_json(message2send)
        logger.debug('make handshake ...!')
        _, _, _, _, _, incoming_data = self.dealer.recv_multipart()
        decoded_data = json.loads(incoming_data.decode())
        if decoded_data['status'] == 1:
            logger.success('handshake was performed successfully')
            if self.connection_type == 'SIGNIN':
                self.start()
        
        else:
            logger.error('failed to make handshake')
        
        logger.debug(decoded_data['message'])


    def remove_ressources(self):
        self.dealer_ctl.unregister(self.dealer)
        self.dealer.close()
        self.ctx.term()
        logger.success('zmq was removed...!')

    def get_list_of_contacts(self):
        self.dealer.send_multipart([
            ZMQClient.DLM, 
            ZMQClient.STS, 
            ZMQClient.DLM, 
            ZMQClient.BYT, 
            ZMQClient.DLM, 
            ZMQClient.DLM 
        ])
    
    def link_to(self, target_pseudo):
        self.dealer.send_multipart([
            ZMQClient.DLM, 
            ZMQClient.LNK, 
            ZMQClient.DLM, 
            ZMQClient.JSN, 
            ZMQClient.DLM, 
            json.dumps({'type': 'request', 'source': self.pseudo, 'target': target_pseudo}).encode()
        ])

    def start(self):
        try:
            screen = '000'
            cv2.namedWindow(screen, cv2.WINDOW_NORMAL)
            cv2.resizeWindow(screen, 400, 400)

            keep_loop = True 
            while keep_loop:
                incoming_events = dict(self.dealer_ctl.poll(10))
                if self.dealer in incoming_events:
                    if incoming_events[self.dealer] == zmq.POLLIN:
                        _, action_type, _, serializer_type, _, encoded_data = self.dealer.recv_multipart()
                            
                        if serializer_type == ZMQClient.JSN:
                            decoded_data = json.loads(encoded_data.decode())
                        if serializer_type == ZMQClient.PKL:
                            decoded_data = pickle.loads(encoded_data)
                        if serializer_type == ZMQClient.BYT:
                            decoded_data = encoded_data.decode()
                        
                        if action_type == ZMQClient.LNK:
                            if decoded_data['type'] == 'question':
                                if decoded_data['contents'] == 'canal?':
                                    rep = input(f'do you want to be linked with {decoded_data["source"]} ?:')
                                    self.dealer.send_multipart([
                                        ZMQClient.DLM, 
                                        ZMQClient.LNK, 
                                        ZMQClient.DLM, 
                                        ZMQClient.JSN, 
                                        ZMQClient.DLM,   
                                        json.dumps({
                                            'type': 'response', 
                                            'contents': rep, 
                                            'source': decoded_data['source'], 
                                            'target': self.pseudo
                                        }).encode()                                  
                                    ])
                            
                            
                            if decoded_data['type'] == 'response':
                               
                                key = decoded_data['key']
                                byte_key = key.encode('utf-8')
                                plain_aes_key = self.rsa_decryption(byte_key)
                                self.canals[decoded_data['target']] = plain_aes_key
                                print(self.canals)

                        if action_type == ZMQClient.STS:
                            print(decoded_data)
            # pseudo:message
            # canals[pseudo] = aes_key
            # aes_encrypt(message, aes_key)
            # send ... branche 
                        
                key_code = cv2.waitKey(25) & 0xFF 
                corresponding_char = chr(key_code)
                if corresponding_char == 'l':
                    self.get_list_of_contacts()
                if corresponding_char == ' ':
                    target_pseudo = input('pseudo:')
                    logger.debug('...')
                    print(target_pseudo)
                    self.link_to(target_pseudo)



            cv2.destroyAllWindows()
        except KeyboardInterrupt as e:
            pass 
        except Exception as e:
            logger.error(e)
        finally:
            self.dealer.send_multipart([
                ZMQClient.DLM, 
                ZMQClient.EXT, 
                ZMQClient.DLM, 
                ZMQClient.BYT, 
                ZMQClient.DLM, 
                self.pseudo.encode() 
            ])
            self.remove_ressources()

@click.command()
@click.option('-s@', '--endpoint', help='server endpoint')
@click.option('-ps', '--pseudo', help='pseudo of user')
@click.option('-pw', '--password', help='pass of user')
@click.option('-ct', '--connection_type', help='type of connection [SIGNIN or SIGNUP]', type=click.Choice(['SIGNIN', 'SIGNUP']), default='SIGNIN')
@click.option('-sc', '--secret', help='path 2 secret.json', default='secret.json', type=click.Path())
def enntrypoint(endpoint, pseudo, password, connection_type, secret):
    client = ZMQClient(endpoint, pseudo, password, connection_type, secret)
    

if __name__ == '__main__':
    enntrypoint()
    