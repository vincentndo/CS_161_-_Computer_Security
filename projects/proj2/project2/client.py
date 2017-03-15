"""Secure client implementation

This is a skeleton file for you to build your secure file store client.

Fill in the methods for the class Client per the project specification.

You may add additional functions and classes as desired, as long as your
Client class conforms to the specification. Be sure to test against the
included functionality tests.
"""

from base_client import BaseClient, IntegrityError
from crypto import CryptoError
import util
import codecs
import binascii
import sys

def path_join(*strings):
    return '/'.join(strings)

class Client(BaseClient):
    def __init__(self, storage_server, public_key_server, crypto_object,
                 username):
        super().__init__(storage_server, public_key_server, crypto_object,
                         username)

    def revolve(self, uid):
        while True:
            res = self.storage_server.get(uid)
            if res is None or res.startswith("[DATA]"):
                return uid
            elif res.startswith("[POINTER]"):
                uid = ret[10:]
            else:
                raise IntegrityError()

    def make_symmetric_key(self):
        key_dict = util.to_json_string(self.private_key)
        key_string = key_dict[100:132]
        return binascii.hexlify(bytes(key_string,'utf-8'))


    def upload(self, name, value):
        # Replace with your implementation
        uid = self.revolve(path_join(self.username, name))

        cipher_name = "AES"
        key = self.make_symmetric_key()
        mode = "CBC"
        IV = self.crypto.get_random_bytes(16)
        cipher_value = self.crypto.symmetric_encrypt(value, key, cipher_name, mode, IV)
        hash_name = "SHA256"
        key_string = str(key,"utf-8")
        tag = self.crypto.message_authentication_code(IV + cipher_value, key_string, hash_name)

        self.storage_server.put(uid, "[DATA] " + IV + tag + cipher_value)
        return True

    def download(self, name):
        # Replace with your implementation
        uid = self.revolve(path_join(self.username, name))
        res = self.storage_server.get(uid)
        if not res:
            return None
        else:
            cipher_name = "AES"
            key = self.make_symmetric_key()
            mode = "CBC"
            IV = res[7:39]
            old_tag = res[39:103]
            cipher_value = res[103:]

            hash_name = "SHA256"
            key_string = str(key,"utf-8")
            new_tag = self.crypto.message_authentication_code(IV + cipher_value, key_string, hash_name)

            if old_tag != new_tag:
                raise IntegrityError()
            else:
                value = self.crypto.symmetric_decrypt(cipher_value, key, cipher_name, mode, IV)
                return value

    def share(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError

    def receive_share(self, from_username, newname, message):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError

    def revoke(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError
