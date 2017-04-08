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
        self.make_unique_symmetric_key()

    def revolve(self, uid):
        while True:
            res = self.storage_server.get(uid)
            if res is None or res.startswith("[DATA]"):
                return uid
            elif res.startswith("[POINTER]"):
                uid = res[10:]
            else:
                raise IntegrityError()

    def sign_and_store(self, value_string, user, data_id):
        encrypted_value_string = self.crypto.asymmetric_encrypt(value_string, self.pks.get_public_key(user))
        signed_encrypted_value_string = self.crypto.asymmetric_sign(encrypted_value_string, self.private_key)
        all_value = (encrypted_value_string, signed_encrypted_value_string)
        all_value_string = util.to_json_string(all_value)
        self.storage_server.put(data_id, "[DATA] " + all_value_string)

    def MAC_and_store(self, value_string, ke, data_id):
        MACed_value_string = self.crypto.message_authentication_code(value_string, ke, "SHA256")
        all_value = (value_string, MACed_value_string)
        all_value_string = util.to_json_string(all_value)
        self.storage_server.put(data_id, "[DATA] " + all_value_string)

    def verify_signature_and_get_value(self, signer, data_id):
        value_string = self.storage_server.get(data_id)
        if not value_string:
            return None
        else:
            try:
                encrypted_content, signed_encrypted_content = util.from_json_string(value_string[7:])
            except:
                raise IntegrityError()

            if self.crypto.asymmetric_verify(encrypted_content, signed_encrypted_content, self.pks.get_public_key(signer)):
                decrypted_content = self.crypto.asymmetric_decrypt(encrypted_content, self.private_key)
                return decrypted_content
            else:
                raise IntegrityError()

    def check_integrity_and_get_value(self, ke, data_id):
        all_value_string = self.storage_server.get(data_id)
        if not all_value_string:
            return None
        else:
            try:
                value_string, MACed_value_string = util.from_json_string(all_value_string[7:])
            except:
                raise IntegrityError()

            if self.crypto.message_authentication_code(value_string, ke, "SHA256") == MACed_value_string:
                return value_string
            else:
                raise IntegrityError()

    def make_unique_symmetric_key(self):
        kid = path_join(self.username, "info")
        all_k = self.storage_server.get(kid)

        if all_k == None:
            k = self.crypto.get_random_bytes(16)
            self.sign_and_store(k, self.username, kid)

    def get_unique_symmetric_key(self):
        kid = path_join(self.username, "info")
        return self.verify_signature_and_get_value(self.username, kid)

    def make_file_keys(self, fid):
        ka = self.crypto.get_random_bytes(16)
        ke = self.crypto.get_random_bytes(16)
        keys = (ka, ke)
        keys_string = util.to_json_string(keys)
        self.sign_and_store(keys_string, self.username, fid)
        return keys

    def get_file_keys(self, name):
        k = self.get_unique_symmetric_key()
        encrypted_filename = self.crypto.message_authentication_code(name, k, "SHA256")
        fid = self.revolve(path_join(self.username, encrypted_filename, "keys"))
        fkeys = self.storage_server.get(fid)

        if fkeys == None:
            return self.make_file_keys(fid)
        else:
            owner, encrypted_original_filename = self.get_owner_and_encrypted_original_filename(name)
        
            if self.username != owner:
                kid = path_join(self.username, encrypted_original_filename, "keys")
                keys_string = self.storage_server.get(kid)
                if not keys_string:
                    return None
                else:
                    try:
                        encrypted_keys_string, signed_encrypted_keys_string = util.from_json_string(keys_string[7:])
                    except:
                        raise IntegrityError()

                if self.crypto.asymmetric_verify(encrypted_keys_string, signed_encrypted_keys_string, self.pks.get_public_key(owner)):
                    keys_string = self.crypto.asymmetric_decrypt(encrypted_keys_string, self.private_key)
                    self.sign_and_store(keys_string, self.username, kid)
                elif self.crypto.asymmetric_verify(encrypted_keys_string, signed_encrypted_keys_string, self.pks.get_public_key(self.username)):
                    pass
                else:
                    raise IntegrityError()

            keys_string = self.verify_signature_and_get_value(self.username, fid)
            keys = util.from_json_string(keys_string)
            return keys

    def upload_helper(self, keys, name, value):
        ka, ke, k = keys
        cipher_name = self.crypto.message_authentication_code(name, k, "SHA256")
        uid = self.revolve(path_join(self.username, cipher_name))

        IV = self.crypto.get_random_bytes(16)
        cipher_value = self.crypto.symmetric_encrypt(value, ke, "AES", "CBC", IV)
        tag = self.crypto.message_authentication_code(IV + cipher_value, ka, "SHA256")
        cipher_all = (IV, cipher_value, tag)
        cipher_all_string = util.to_json_string(cipher_all)

        self.storage_server.put(uid, "[DATA] " + cipher_all_string)
        return True


    def upload(self, name, value):
        # Replace with your implementation
        ka, ke = self.get_file_keys(name)
        k = self.get_unique_symmetric_key()
        keys = (ka, ke, k)
        return self.upload_helper(keys, name, value)

    def download(self, name):
        # Replace with your implementation
        ka, ke= self.get_file_keys(name)
        k = self.get_unique_symmetric_key()
        cipher_name = self.crypto.message_authentication_code(name, k, "SHA256")
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

    def get_owner_and_encrypted_original_filename(self, filename):
        k = self.get_unique_symmetric_key()
        cipher_filename = self.crypto.message_authentication_code(filename, k, "SHA256")
        uid = path_join(self.username, cipher_filename)
        while True:
            res = self.storage_server.get(uid)
            if res is None or res.startswith("[DATA]"):
                return uid.split("/")
            elif res.startswith("[POINTER]"):
                uid = res[10:]
            else:
                raise IntegrityError()

    def share_keys_with_user(self, user, encrypted_original_filename, keys):
        fid = path_join(user, encrypted_original_filename, "keys")
        keys_string = util.to_json_string(keys)
        self.sign_and_store(keys_string, user, fid)

    def share(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        keys = self.get_file_keys(name)
        ka, ke = keys
        file_info = self.get_owner_and_encrypted_original_filename(name)
        encrypted_original_filename = file_info[1]

        share_id = path_join(self.username, encrypted_original_filename, "shared_with")
        share_list_string = self.storage_server.get(share_id)
        if share_list_string == None:
            share_list = [user]
        else:
            share_list_string = self.check_integrity_and_get_value(ke, share_id)
            share_list = util.from_json_string(share_list_string)
            share_list.append(user)

        share_list_string = util.to_json_string(share_list)
        self.MAC_and_store(share_list_string, ke, share_id)

        self.share_keys_with_user(user, encrypted_original_filename, keys)

        self.make_bridge(user, encrypted_original_filename)

        keys_filename = (ka, ke, encrypted_original_filename)
        keys_filename_string = util.to_json_string(keys_filename)
        encrypted_keys_filename_string = self.crypto.asymmetric_encrypt(keys_filename_string, self.pks.get_public_key(user))
        signed_encrypted_keys_filename_string = self.crypto.asymmetric_sign(encrypted_keys_filename_string, self.private_key)
        msg = util.to_json_string((encrypted_keys_filename_string, signed_encrypted_keys_filename_string))
        return msg

    def re_sign_keys(self, keys_link, old_signer):
        keys_string = self.verify_signature_and_get_value(old_signer, keys_link)
        self.sign_and_store(keys_string, self.username, keys_link)

    def receive_share(self, from_username, newname, message):
        # Replace with your implementation (not needed for Part 1)
        try: 
            encrypted_keys_filename_string, signed_encrypted_keys_filename_string = util.from_json_string(message)
        except:
            raise IntegrityError()

        if self.crypto.asymmetric_verify(encrypted_keys_filename_string, signed_encrypted_keys_filename_string, self.pks.get_public_key(from_username)):
            decrypted_keys_filename_string = self.crypto.asymmetric_decrypt(encrypted_keys_filename_string, self.private_key)
            ka, ke, encrypted_original_filename = util.from_json_string(decrypted_keys_filename_string)

            k = self.get_unique_symmetric_key()
            encrypted_newfilename = self.crypto.message_authentication_code(newname, k, "SHA256")
            fid = path_join(self.username, encrypted_newfilename, "keys")
            keys_link = path_join(self.username, encrypted_original_filename, "keys")
            self.re_sign_keys(keys_link, from_username)
            self.storage_server.put(fid, "[POINTER] " + keys_link)

            uid = path_join(self.username, encrypted_newfilename)
            link = path_join(self.username, encrypted_original_filename)
            self.storage_server.put(uid, "[POINTER] " + link)
        else:
            raise IntegrityError()

    def revoke(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        old_keys = self.get_file_keys(name)
        old_ka, old_ke = old_keys
        k = self.get_unique_symmetric_key()
        cipher_name = self.crypto.message_authentication_code(name, k, "SHA256")
        interface_id = path_join(user, cipher_name)
        self.storage_server.delete(interface_id)

        new_keys = self.re_encrypt_file(name)
        new_ka, new_ke = new_keys

        owner, encrypted_original_filename = self.get_owner_and_encrypted_original_filename(name)
        share_id = path_join(self.username, encrypted_original_filename, "shared_with")
        share_list_string = self.check_integrity_and_get_value(old_ke, share_id)
        share_list = util.from_json_string(share_list_string)

        if user in share_list:
            share_list.remove(user)

        self.re_distribute_keys(share_id, share_list, encrypted_original_filename, old_ke, new_keys)

    def re_encrypt_file(self, name):
        k = self.get_unique_symmetric_key()
        encrypted_filename = self.crypto.message_authentication_code(name, k, "SHA256")
        fid = self.revolve(path_join(self.username, encrypted_filename, "keys"))
        value = self.download(name)
        ka, ke = self.make_file_keys(fid)
        all_keys = (ka, ke, k)
        self.upload_helper(all_keys, name, value)
        return (ka, ke)

    def re_distribute_keys(self, share_id, share_list, encrypted_original_filename, old_ke, new_keys):
        share_list_string = util.to_json_string(share_list)
        self.MAC_and_store(share_list_string, new_keys[1], share_id)
        if share_list == None or len(share_list) == 0:
            return
        else:
            for user in share_list:
                self.share_keys_with_user(user, encrypted_original_filename, new_keys)

                user_share_id = path_join(user, encrypted_original_filename, "shared_with")
                user_share_list_string = self.check_integrity_and_get_value(old_ke, user_share_id)
                if user_share_list_string is not None:
                    user_share_list = util.from_json_string(user_share_list_string)
                    self.re_distribute_keys(user_share_id, user_share_list, encrypted_original_filename, old_ke, new_keys)
