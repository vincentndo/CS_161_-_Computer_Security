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
                uid = res[10:]
            else:
                raise IntegrityError()

    def make_unique_symmetric_key(self):
        key_dict = util.to_json_string(self.private_key)
        key_string = key_dict[100:132]
        key = binascii.hexlify(bytes(key_string,'utf-8'))
        return str(key,"utf-8")

    def is_owner(self, uid):
        res = self.storage_server.get(uid)
        if res.startswith("[DATA]"):
            return True
        else:
            return False

    def get_file_keys(self, name):
        unique_symmetric_key = self.make_unique_symmetric_key()
        encrypted_filename = self.crypto.message_authentication_code(name, unique_symmetric_key, "SHA256")
        fid = path_join(self.username, encrypted_filename, "keys")
        fkeys = self.storage_server.get(fid)

        if fkeys == None:
            ka = self.crypto.get_random_bytes(16)
            ke = self.crypto.get_random_bytes(16)
            kn = self.crypto.get_random_bytes(16)
            keys = (ka, ke, kn)
            keys_string = util.to_json_string(keys)
            encrypted_keys_string = self.crypto.asymmetric_encrypt(keys_string, self.pks.get_public_key(self.username))
            signed_encrypted_keys_string = self.crypto.asymmetric_sign(encrypted_keys_string, self.private_key)
            all_keys_string = util.to_json_string((encrypted_keys_string, signed_encrypted_keys_string))
            self.storage_server.put(fid, all_keys_string)
            return keys
        else:
            try: 
                encrypted_keys_string, signed_encrypted_keys_string = util.from_json_string(fkeys)
            except:
                raise IntegrityError()

            if self.crypto.asymmetric_verify(encrypted_keys_string, signed_encrypted_keys_string, self.pks.get_public_key(self.username)):
                decrypted_keys_string = self.crypto.asymmetric_decrypt(encrypted_keys_string, self.private_key)
                keys = util.from_json_string(decrypted_keys_string)
                return keys
            else:
                raise IntegrityError()

    def upload(self, name, value):
        # Replace with your implementation      
        ka, ke, kn = self.get_file_keys(name)
        cipher_name = self.crypto.message_authentication_code(name, kn, "SHA256")
        uid = self.revolve(path_join(self.username, cipher_name))

        IV = self.crypto.get_random_bytes(16)
        cipher_value = self.crypto.symmetric_encrypt(value, ke, "AES", "CBC", IV)
        tag = self.crypto.message_authentication_code(IV + cipher_value, ka, "SHA256")
        cipher_all = (IV, cipher_value, tag)
        cipher_all_string = util.to_json_string(cipher_all)

        self.storage_server.put(uid, "[DATA] " + cipher_all_string)
        return True

    def download(self, name):
        # Replace with your implementation
        ka, ke, kn = self.get_file_keys(name)
        cipher_name = self.crypto.message_authentication_code(name, kn, "SHA256")
        uid = self.revolve(path_join(self.username, cipher_name))
        res = self.storage_server.get(uid)

        if not res:
            return None
        else:
            cipher_all_string = res[7:]
            try:
                IV, cipher_value, old_tag = util.from_json_string(cipher_all_string)
            except:
                raise IntegrityError()

            new_tag = self.crypto.message_authentication_code(IV + cipher_value, ka, "SHA256")

            if old_tag != new_tag:
                raise IntegrityError()
            else:
                value = self.crypto.symmetric_decrypt(cipher_value, ke, "AES", "CBC", IV)
                return value

    def make_bridge(self, user, cipher_fname):
        interface_id = path_join(user, cipher_fname)
        sharer_id = path_join(self.username, cipher_fname)
        self.storage_server.put(interface_id, "[POINTER] " + sharer_id)
        return interface_id

    def share(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        keys_string = self.get_file_keys(name)
        ka, ke, kn = keys_string
        cipher_name = self.crypto.message_authentication_code(name, kn, "SHA256")
        interface_id = self.make_bridge(user, cipher_name)
        keys_id = (ka, ke, kn, interface_id)
        keys_id_string = util.to_json_string(keys_id)

        encrypted_keys_id_string = self.crypto.asymmetric_encrypt(keys_id_string, self.pks.get_public_key(user))
        signed_encrypted_keys_id_string = self.crypto.asymmetric_sign(encrypted_keys_id_string, self.private_key)
        msg = util.to_json_string((encrypted_keys_id_string, signed_encrypted_keys_id_string))
        return msg

    def create_link(self, encrypted_newfilename, link):
        uid = path_join(self.username, encrypted_newfilename)
        self.storage_server.put(uid, "[POINTER] " + link)

    def receive_share(self, from_username, newname, message):
        # Replace with your implementation (not needed for Part 1)
        try: 
            encrypted_keys_id_string, signed_encrypted_keys_id_string = util.from_json_string(message)
        except:
            raise IntegrityError()

        if self.crypto.asymmetric_verify(encrypted_keys_id_string, signed_encrypted_keys_id_string, self.pks.get_public_key(from_username)):
            decrypted_keys_id_string = self.crypto.asymmetric_decrypt(encrypted_keys_id_string, self.private_key)
            ka, ke, kn, interface_id = util.from_json_string(decrypted_keys_id_string)

            unique_symmetric_key = self.make_unique_symmetric_key()
            encrypted_newfilename = self.crypto.message_authentication_code(newname, unique_symmetric_key, "SHA256")
            fid = path_join(self.username, encrypted_newfilename, "keys")

            keys = (ka, ke, kn)
            keys_string = util.to_json_string(keys)
            encrypted_keys_string = self.crypto.asymmetric_encrypt(keys_string, self.pks.get_public_key(self.username))
            signed_encrypted_keys_string = self.crypto.asymmetric_sign(encrypted_keys_string, self.private_key)
            all_keys_string = util.to_json_string((encrypted_keys_string, signed_encrypted_keys_string))
            self.storage_server.put(fid, all_keys_string)
            self.create_link(encrypted_newfilename, interface_id)
        else:
            raise IntegrityError()


    def revoke(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        keys_string = self.get_file_keys(name)
        ka, ke, kn = keys_string
        cipher_name = self.crypto.message_authentication_code(name, kn, "SHA256")
        interface_id = path_join(user, cipher_name)
        self.storage_server.delete(interface_id)
