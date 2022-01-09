import os 
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

"""
    A et B et C 
        # asy : RSA (pub_key, prv_key)
            $ robuste | slow 
        # sym : AES (unq_key) 
            $ robutes | fast 
    
    niang envoie sa clé publique a djim 
    djim utilsie cette clé publique pour crypter la _unq_key 
    djim envoie _unq_key a niang 

    dembo recupere _unq_key en sniffant le reseau mais dembo ne peut dechiffrer _unq_key
    niang recoit _unq_key et utilise prv_key pour dechiffrer _unq_key
    niang obtient unq_key from _unq_key avec sa prv_key 

    unq_key AES 

    niang envoie pub_key au server qui le donne a djim 
    djim envoie pub_key au server qui le donne à niang 

    server envoie left or right a soit djim ou niang 

    niang crée une partie de unq_key_left (128 bits)
    djim crée la partie droite de clé unq_key_right(128 bits)

    niang crypte avec la pub_key de djim, unq_key_left et lenvoie au server qui le donne a djim
    djim crypte avec la pub_key de niang et envoie unq_key_right au server qui le donne a niang

    niang peut utiliser sa prv_key pour dechiffrer unq_key_right et combiner 
    unq_key_left avec unq_key_right pour avoir unq_key 

    djim peut utiliser sa prv_key pour dechiffrer unq_key_left et combiner 
    unq_key_left avec unq_key_right pour avoir unq_key 


    djim et niang peuvent alors communiquer via unq_key par AES 
"""

class ZMQClient:
    TXT = b'txt'
    SND = b'snd'
    IMG = b'img'

    BYT = b'byt'
    JSN = b'jsn'
    PKL = b'pkl'

    DLM = b''
    ERR = b'err'
    HSK = b'hsk'
    STS = b'sts'

    def __init__(self, endpoint, pseudo, password, connection_type='SIGNIN'):
        self.pseudo = pseudo 
        self.password = password 
        self.endpoint = endpoint 
        self.connection_type = connection_type

        logger.debug('rsa key generation ...!')
        key = RSA.generate(2048)
        self.pem_prv_key = key.export_key('PEM')
        self.pem_pub_key = key.publickey().exportKey('PEM')
    
        self.pub_key = RSA.import_key(self.pem_pub_key)
        self.prv_key = RSA.import_key(self.pem_prv_key)    

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
        return plain.decode('utf-8')

    def aes_encryption(self, plain):
        pass 

    def aes_decryption(self, b64_cipher):
        pass 

    def make_hsk(self):
        # _, action_type, _, serializer_type, _, encoded_data
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
        else:
            logger.error('failed to make handshake')
        
        print(decoded_data['message'])

@click.command()
@click.option('-s@', '--endpoint', help='server endpoint')
@click.option('-ps', '--pseudo', help='pseudo of user')
@click.option('-pw', '--password', help='pass of user')
@click.option('-ct', '--connection_type', help='type of connection [SIGNIN or SIGNUP]')
def enntrypoint(endpoint, pseudo, password, connection_type):
    client = ZMQClient(endpoint, pseudo, password, connection_type)
    

if __name__ == '__main__':
    enntrypoint()
    