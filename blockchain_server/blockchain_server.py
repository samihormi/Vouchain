import argparse
import os
import traceback
import yaml

from collections import OrderedDict

import binascii

import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.kdf import x963kdf
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption, \
    BestAvailableEncryption
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.exceptions import InvalidSignature

from OpenSSL import crypto

import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4

import requests
from flask import Flask, jsonify, request, render_template
from flask_cors import CORS

MINING_SENDER = "THE BLOCKCHAIN"
MINING_REWARD = 1
MINING_DIFFICULTY = 2


class Blockchain:

    def __init__(self, argms):

        self.args = argms
        self.transactions = []
        self.applications = []
        self.chain = []
        self.nodes = set()
        # Generate random number to be used as node_id
        self.node_id = str(uuid4()).replace('-', '')
        # Create genesis block
        self.public_key, self.private_key, self.main_key = self.generate_keypair('ecc', 'secp256r1', argms.admin_pass)
        self.submit_transaction(sender_public_key=self.format_key(),receiver_public_key="",
                                voucher_number=-1, value=0, signature="")
        self.create_block(block_type="transactions", nonce=0, previous_hash='00')

        # self.encrypt("sami is here",)

    def encrypt(self, message, receiver_public_key):
        shared_key = self.main_key.exchange(ec.ECDH(), receiver_public_key)
        sender_public_key = self.main_key.public_key()
        point = sender_public_key.public_numbers().encode_point()
        iv = '000000000000'
        xkdf = x963kdf.X963KDF(
            algorithm=SHA256(),
            length=32,
            sharedinfo='',
            backend=default_backend()
        )
        key = xkdf.derive(shared_key)
        encryptor = Cipher(
            AES(key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()
        ciphertext = encryptor.update(message) + encryptor.finalize()
        return point + encryptor.tag + ciphertext

        data = b'Sami is handsome'
        algoer = AES(
            self.byt_private_key)  # 这里的AES算法（若要换成des算法，这里换成TripleDES，该加密库中，DES 事实上等于 TripleDES 的密钥长度为 64bit 时的加解密）
        cipher = Cipher(algoer, modes.CBC(iv), backend=default_backend())  # 这里的CBC模式
        print("Original data {}".format(data))
        print("Encrypted data {}".format(self.enc(data, algoer, cipher)))
        print("Decrypted data {}".format(self.dec(data, algoer, cipher)))

    def enc(self, bitstring, algoer, cipher):
        padder = PKCS7(algoer.block_size).padder()
        bitstring = padder.update(bitstring) + padder.finalize()
        encryptor = cipher.encryptor()
        return encryptor.update(bitstring) + encryptor.finalize()

    def dec(self, bitstring, algoer, cipher):
        decryptor = cipher.decryptor()
        ddata = decryptor.update(bitstring) + decryptor.finalize()
        unpadder = PKCS7(algoer.block_size).unpadder()
        return unpadder.update(ddata) + unpadder.finalize()

    def register_node(self, node_url):
        """
        Add a new node to the list of nodes
        """
        # Checking node_url has valid format
        parsed_url = urlparse(node_url)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    def verify_transaction_signature(self, transaction_data, sender_public_key, signature):
        """
        Check that the provided signature corresponds to transaction
        signed by the public key (sender_address)
        """
        signature = binascii.unhexlify(str(signature).encode('utf8'))
        data = str(transaction_data).encode('utf8')
        public_key = (str.encode(sender_public_key)).replace(b'\\n', b'\n')
        # print("Newest {}".format(public_key))
        # print()

        puk = crypto.load_publickey(crypto.FILETYPE_PEM, public_key)

        x509 = crypto.X509()
        x509.set_pubkey(puk)
        # print()
        # print(puk)
        # print(data)
        # print(signature)

        # ans = crypto.verify(x509, signature, data, 'sha256')
        if crypto.verify(x509, signature, data, 'sha256') is None:
            print('Verification OKK')
        else:
            print('Verification failedd')

        return crypto.verify(x509, signature, data, 'sha256')

    def verify_registration_signature(self, registration_data, public_key, signature):
        """
        Check that the provided signature corresponds to transaction
        signed by the public key (sender_address)
        """

        signature = binascii.unhexlify(str(signature).encode('utf8'))
        data = str(registration_data).encode('utf8')
        public_key = (str.encode(public_key)).replace(b'\\n', b'\n')
        # print("Newest {}".format(public_key))
        # print()

        puk = crypto.load_publickey(crypto.FILETYPE_PEM, public_key)

        x509 = crypto.X509()
        x509.set_pubkey(puk)
        # print()
        # print(puk)
        # print(data)
        # print(signature)

        # ans = crypto.verify(x509, signature, data, 'sha256')
        if crypto.verify(x509, signature, data, 'sha256') is None:
            print('Verification OK')
        else:
            print('Verification failed')

        return crypto.verify(x509, signature, data, 'sha256')

        # print(ans)

    def format_key(self):
        pubkey_bytes = crypto.dump_publickey(crypto.FILETYPE_PEM, self.public_key).decode('utf8')
        print("Original {}".format(pubkey_bytes))
        public_key = pubkey_bytes.replace('\n', '\\n')
        return public_key

    def submit_transaction(self, sender_public_key, receiver_public_key, voucher_number, value, signature):
        """
        Add a transaction to transactions array if the signature verified
        """

        transaction = OrderedDict({'sender_public_key': sender_public_key,
                                   'receiver_public_key': receiver_public_key,
                                   'voucher_number': voucher_number,
                                   'value': value})

        if signature == "": #Adding the server public key
            print("Confirmed intitialization transaction!")
            self.transactions.append(transaction)
            return len(self.chain) + 1
        transaction_verification = self.verify_transaction_signature(transaction, sender_public_key, signature)
        if transaction_verification is None:
            print("Confirmed Signature Transaction!")
            self.transactions.append(transaction)
            return len(self.chain) + 1
        else:
            return False

    def submit_registration(self, applicant_first_name, applicant_last_name, applicant_hkid, applicant_email,
                            applicant_public_key, signature):
        """
        Add a transaction to transactions array if the signature verified
        """
        transaction = OrderedDict({'applicant_first_name': applicant_first_name,
                                   'applicant_last_name': applicant_last_name,
                                   'applicant_hkid': applicant_hkid,
                                   'applicant_email': applicant_email,
                                   # 'applicant_public_key': self.public_key
                                   })

        # Manages transactions from wallet to another wallet

        registration_verification = self.verify_registration_signature(transaction, applicant_public_key, signature)
        if registration_verification is None:
            print("Confirmed Signature Registration!")
            register_publicKey = OrderedDict({'sender_public_key': applicant_public_key,
                                              'applicant_hkid': applicant_hkid,
                                              'receiver_public_key': '',
                                              'voucher_number': -1,
                                              'value': 0})
            self.applications.append(register_publicKey)
            return len(self.chain) + 1
        else:
            print("Incorrect Signature !")
            return False

    def create_block(self, block_type, nonce, previous_hash):
        """
        Add a block of transactions to the blockchain_server
        """
        if block_type == "applications":
            block = {'block_number': len(self.chain) + 1,
                     'timestamp': time(),
                     'transactions': self.applications,
                     'nonce': nonce,
                     'previous_hash': previous_hash}
            self.applications = []
        else:
            block = {'block_number': len(self.chain) + 1,
                     'timestamp': time(),
                     'transactions': self.transactions,
                     'nonce': nonce,
                     'previous_hash': previous_hash}
            self.transactions = []

        # Reset the current list of transactions

        self.chain.append(block)
        return block

    def generate_keypair(self, hash_type, key_size_curve, admin):
        try:
            with open(os.getcwd() + '/blockchain_server/config.yaml') as f:
                config = yaml.load(f, Loader=yaml.FullLoader)
        except FileNotFoundError:
            print('ERROR in reading config file: ')
            traceback.print_exc()

        os.makedirs(config['public_root'], exist_ok=True)

        # Check type of hash function
        for nodecfg in config['server']:
            key_size_curve = key_size_curve.lower()
            if hash_type.lower() == 'rsa':
                if key_size_curve in ['1024', '2048', '4096']:
                    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size_curve)
                else:
                    print('Unsupported key curve: ' + key_size_curve + '\n')
                    return None

            else:
                if key_size_curve not in ['secp256r1', 'secp384r1', 'secp521r1']:
                    print('Unsupported key curve: ' + key_size_curve + '\n')
                    return None
                if key_size_curve == 'secp256r1':
                    key = ec.generate_private_key(ec.SECP256R1(), default_backend())
                elif key_size_curve == 'secp384r1':
                    key = ec.generate_private_key(ec.SECP384R1(), default_backend())
                elif key_size_curve == 'secp521r1':
                    key = ec.generate_private_key(ec.SECP521R1(), default_backend())

                if nodecfg['type'] == 'client':
                    private_key = key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.TraditionalOpenSSL,
                                                    encryption_algorithm=NoEncryption())
                else:
                    private_key = key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.TraditionalOpenSSL,
                                                    encryption_algorithm=NoEncryption())
                    # private_key = key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.TraditionalOpenSSL,
                    #                                 encryption_algorithm=BestAvailableEncryption(password=admin))

            public_key = key.public_key().public_bytes(encoding=Encoding.PEM,
                                                       format=PublicFormat.SubjectPublicKeyInfo)

            prk = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key)
            puk = crypto.load_publickey(crypto.FILETYPE_PEM, public_key)
            os.makedirs(nodecfg['root'], exist_ok=True)
            print('1z')
            print(public_key)
            # print(private_key,public_key)
            # print(prk,puk)
            # print(base64.b64encode(private_key))
            # print(base64.b64encode(public_key))
            # print()
            # print()
            # print((base64.b64encode(private_key)).decode('ascii'))
            # print(private_key)

            # Same output as public_key
            # print(crypto.dump_publickey(crypto.FILETYPE_PEM, puk))

            with open(os.path.join(nodecfg['root'], 'private.pem'), 'wb') as private_file_f:
                private_file_f.write(private_key)
            with open(os.path.join(config['public_root'], '{}.pub.pem'.format(nodecfg['id'])),
                      'wb') as public_file_f:
                public_file_f.write(public_key)

            # print(public_key)
            # print('The other public key is ' + binascii.hexlify(public_key).decode('ascii'))
            print('Returned public key')
            return puk, prk, key

    def hash(self, block):
        """
        Create a SHA-256 hash of a block
        """
        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()

        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, proof_type):
        """
        Proof of work algorithm
        """
        last_block = self.chain[-1]
        last_hash = self.hash(last_block)

        nonce = 0
        if proof_type == 'application':
            while self.valid_proof(self.applications, last_hash, nonce) is False:
                nonce += 1
        else:
            while self.valid_proof(self.transactions, last_hash, nonce) is False:
                nonce += 1

        return nonce

    def valid_proof(self, trans_type, last_hash, nonce, difficulty=MINING_DIFFICULTY):
        """
        Check if a hash value satisfies the mining conditions. This function is used within the proof_of_work function.
        """
        guess = (str(trans_type) + str(last_hash) + str(nonce)).encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:difficulty] == '0' * difficulty

    def valid_chain(self, chain):
        """
        Check if a blockchain_server is valid
        """
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            # print(last_block)
            # print(block)
            # print("\n-----------\n")
            # Check that the hash of the block is correct
            if block['previous_hash'] != self.hash(last_block):
                return False

            # Check that the Proof of Work is correct
            # Delete the reward transaction
            transactions = block['transactions'][:-1]
            # Need to make sure that the dictionary is ordered. Otherwise we'll get a different hash
            transaction_elements = ['sender_address', 'recipient_address', 'value']
            transactions = [OrderedDict((k, transaction[k]) for k in transaction_elements) for transaction in
                            transactions]

            if not self.valid_proof(transactions, block['previous_hash'], block['nonce'], MINING_DIFFICULTY):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        Resolve conflicts between blockchain_server's nodes
        by replacing our chain with the longest one in the network.
        """
        neighbours = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            print('http://' + node + '/chain')
            response = requests.get('http://' + node + '/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False

    def verify(self, key, private_key, public_key):
        pk = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key)
        puk = crypto.load_publickey(crypto.FILETYPE_PEM, public_key)
        # print(public_key)
        # print(private_key)
        # print(pk)
        # print(puk)
        # print(public_key.decode())
        # print(private_key.decode())
        data = b"dad"
        signature_algorithm = ec.ECDSA(SHA256())
        signature = key.sign(data, signature_algorithm)
        print('Signature: 0x%s' % signature.hex())

        # Verify
        try:
            key.public_key().verify(signature, data, signature_algorithm)
            print('Verification OK')
        except InvalidSignature:
            print('Verification failed')

        signature2 = crypto.sign(pkey=pk, data=data, digest='sha256')
        # Verify
        # the verify() function expects that the public key is
        # wrapped in an X.509 certificate
        x509 = crypto.X509()
        x509.set_pubkey(puk)
        try:
            crypto.verify(x509, signature2, data, 'sha256')
            print('Verification OK')
        except InvalidSignature:
            print('Verification failed')

    def add_vouchers(self):
        for i in range(20):
            if i < 5:
                return blockchain.submit_transaction(receiver_public_key=self.public_key, voucher_number=i + 1,
                                                     value=50, signature="")
            elif i < 14:
                return blockchain.submit_transaction(receiver_public_key=self.public_key, voucher_number=i + 1,
                                                     value=100,
                                                     signature="")
            else:
                return blockchain.submit_transaction(receiver_public_key=self.public_key, voucher_number=i + 1,
                                                     value=500,
                                                     signature="")


# Instantiate the Node
app = Flask(__name__)
CORS(app)


@app.route('/')
def index():
    return render_template('./registrations_approval.html')


@app.route('/configure')
def configure():
    return render_template('./configure.html')


@app.route('/transaction')
def transact():
    return render_template('./transactions_approval.html')


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.form

    # Check that the required fields are in the POST'ed data
    required = ['sender_public_key', 'receiver_public_key', 'voucher_number', 'value', 'signature']
    if not all(k in values for k in required):
        print('Values are missing')
        return 'Missing values', 400
    # Create a new Transaction
    transaction_result = blockchain.submit_transaction(values['sender_public_key'], values['receiver_public_key'],
                                                       values['voucher_number'], values["value"], values['signature'])

    if not transaction_result:
        response = {'message': 'Invalid Transaction!'}
        return jsonify(response), 406
    else:
        response = {'message': 'Transaction will be added to Block ' + str(transaction_result)}
        return jsonify(response), 201


@app.route('/registrations/new', methods=["POST"])
def new_registration():
    values = request.form
    # print(values)
    # Check that the required fields are in the POST'ed data
    required = ['applicant_first_name', 'applicant_last_name', 'applicant_hkid',
                'applicant_email', 'applicant_public_key', 'signature']
    if not all(k in values for k in required):
        print('MISSSSSSSSS')
        return 'Missing values', 400

    # Create a new Registration
    registration_result = blockchain.submit_registration(values['applicant_first_name'], values['applicant_last_name'],
                                                         values['applicant_hkid'], values['applicant_email'],
                                                         values['applicant_public_key'], values['signature'])
    print('Registration submitted')
    if not registration_result:
        response = {'message': 'Invalid Transaction!'}
        return jsonify(response), 406
    else:
        response = {'message': 'Registration will be added to Block ' + str(registration_result)}
        return jsonify(response), 201


@app.route('/transactions/get', methods=['GET'])
def get_transactions():
    # Get transactions from transactions pool
    transactions = blockchain.transactions

    response = {'transactions': transactions}
    return jsonify(response), 200


@app.route('/applications/get', methods=['GET'])
def get_applications():
    # Get applications from users
    applications = blockchain.applications

    response = {'applications': applications}
    return jsonify(response), 200


@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


@app.route('/start', methods=['GET'])
def start():
    # Instantiate the blockchain with the genesis block
    if len(blockchain.applications) == 0 and len(blockchain.chain) > 1:
        print("Yes sir")
        return jsonify({'message': "Empty"}), 200

    block = blockchain.chain[-1]

    response = {
        'message': "New Block Forged",
        'block_number': block['block_number'],
        'transactions': block['transactions'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash'],
    }
    print(response)
    return jsonify(response), 200


@app.route('/approve_registration', methods=['GET'])
def approve_registration():
    # We run the proof of work algorithm to get the next proof...
    if len(blockchain.applications) == 0:
        print("Nothing to add")
        return jsonify({'message': "Empty"}), 200

    print('Adding registration')
    # Get the last block
    last_block = blockchain.chain[-1]
    nonce = blockchain.proof_of_work('application')

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.create_block('applications', nonce, previous_hash)

    response = {
        'message': "New Block Forged",
        'block_number': block['block_number'],
        'transactions': block['transactions'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash'],
    }

    print(response)

    return jsonify(response), 200


@app.route('/approve_transaction', methods=['GET'])
def approve_transaction():
    # We run the proof of work algorithm to get the next proof...
    if len(blockchain.transactions) == 0:
        print("Nothing to add")
        return jsonify({'message': "Empty"}), 200

    print('Adding transaction')
    # Get the last block
    last_block = blockchain.chain[-1]
    nonce = blockchain.proof_of_work('transaction')

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.create_block('transactions', nonce, previous_hash)

    response = {
        'message': "New Block Forged",
        'block_number': block['block_number'],
        'transactions': block['transactions'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash'],
    }

    print(response)

    return jsonify(response), 200


# @app.route('/approve', methods=['GET'])
# def approve1():
#     # We run the proof of work algorithm to get the next proof...
#     last_block = blockchain.chain[-1]
#     print("last block is {}".format(last_block))
#     nonce = blockchain.proof_of_work('application')
#
#     blockchain.submit_transaction()
#
#     # Forge the new Block by adding it to the chain
#     previous_hash = blockchain.hash(last_block)
#     block = blockchain.create_block(nonce, previous_hash,'applications')
#     print("the ultimate block {}".format(block))
#     response = {
#         'message': "New Block Forged",
#         'block_number': block['block_number'],
#         'applications': block['applications'],
#         'server_public_key': block['server_public_key'],
#         'voucher_number': block['voucher_number'],
#         'value': block['value'],
#         'nonce': block['nonce'],
#         'previous_hash': block['previous_hash'],
#     }
#     return jsonify(response), 200


@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.form
    nodes = values.get('nodes').replace(" ", "").split(',')

    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': [node for node in blockchain.nodes],
    }
    return jsonify(response), 201


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }
    return jsonify(response), 200


@app.route('/nodes/get', methods=['GET'])
def get_nodes():
    nodes = list(blockchain.nodes)
    response = {'nodes': nodes}
    return jsonify(response), 200


if __name__ == '__main__':
    # Instantiate the Blockchain
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    parser.add_argument('-a', '--admin_pass', default=b'test', help='Enter the password of admin')  # 9k8ov7oucher
    args = parser.parse_args()
    blockchain = Blockchain(args)
    app.run(host='127.0.0.1', port=args.port)
