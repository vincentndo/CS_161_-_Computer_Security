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
import sys

chunk = 512

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

    def MAC_and_store(self, value_string, ka, data_id):
        MACed_value_string = self.crypto.message_authentication_code(value_string, ka, "MD5")
        all_value = (value_string, MACed_value_string)
        all_value_string = util.to_json_string(all_value)
        self.storage_server.put(data_id, "[DATA] " + all_value_string)

    def AES_CBC_and_store(self, string, keys, uid):
        ka, ke = keys
        IV = self.crypto.get_random_bytes(16)
        cipher_string = self.crypto.symmetric_encrypt(string, ke, "AES", "CBC", IV)
        tag = self.crypto.message_authentication_code(IV + cipher_string, ka, "MD5")
        cipher_all = (IV, cipher_string, tag)
        cipher_all_string = util.to_json_string(cipher_all)
        self.storage_server.put(uid, "[DATA] " + cipher_all_string)

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

    def check_integrity_and_get_value(self, ka, data_id):
        all_value_string = self.storage_server.get(data_id)
        if not all_value_string:
            return None
        else:
            try:
                value_string, MACed_value_string = util.from_json_string(all_value_string[7:])
            except:
                raise IntegrityError()

            if self.crypto.message_authentication_code(value_string, ka, "MD5") == MACed_value_string:
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
        encrypted_filename = self.crypto.message_authentication_code(name, k, "MD5")
        half = int(len(encrypted_filename)/2)
        encrypted_filename = encrypted_filename[:half]
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

    def upload_helper(self, all_keys, name, value):
        ka, ke, k = all_keys
        keys = (ka, ke)
        cipher_name = self.crypto.message_authentication_code(name, k, "MD5")
        half = int(len(cipher_name)/2)
        cipher_name = cipher_name[:half]
        uid = self.revolve(path_join(self.username, cipher_name))

        chunk_num = int( len(value) / chunk + 1 )
        self.AES_CBC_and_store(str(chunk_num), keys, uid)

        for i in range(chunk_num):
            uid_i = path_join(uid, str(i))
            start, end = i * chunk, min(len(value), (i + 1) * chunk)
            value_i = value[start : end]
            self.AES_CBC_and_store(value_i, keys, uid_i)

        return True

    def upload_helper_effective(self, all_keys, name, value):
        ka, ke, k = all_keys
        keys = (ka, ke)
        cipher_name = self.crypto.message_authentication_code(name, k, "MD5")
        half = int(len(cipher_name)/2)
        cipher_name = cipher_name[:half]
        uid = self.revolve(path_join(self.username, cipher_name))
        merkle_tree = MerkleTree(self, value)

        res = self.storage_server.get(uid)
        if not res:
            chunk_num = int( len(value) / chunk + 1 )
            self.AES_CBC_and_store(str(chunk_num), keys, uid)

            for i in range(chunk_num):
                uid_i = path_join(uid, str(i))
                start, end = i * chunk, min(len(value), (i + 1) * chunk)
                value_i = value[start : end]
                self.AES_CBC_and_store(value_i, keys, uid_i)

            merkle_tree.store_tree(keys, uid)

        else:
            merkle_tree.update(keys, uid)

        return True

    def upload(self, name, value):
        # Replace with your implementation
        ka, ke = self.get_file_keys(name)
        k = self.get_unique_symmetric_key()
        all_keys = (ka, ke, k)
        if len(value) < 2**15:
            return self.upload_helper(all_keys, name, value)
        else:
            return self.upload_helper_effective(all_keys, name, value)

    def download(self, name):
        # Replace with your implementation
        ka, ke= self.get_file_keys(name)
        k = self.get_unique_symmetric_key()
        cipher_name = self.crypto.message_authentication_code(name, k, "MD5")
        half = int(len(cipher_name)/2)
        cipher_name = cipher_name[:half]
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

            new_tag = self.crypto.message_authentication_code(IV + cipher_value, ka, "MD5")

            if old_tag != new_tag:
                raise IntegrityError()
            else:
                chunk_num_string = self.crypto.symmetric_decrypt(cipher_value, ke, "AES", "CBC", IV)
                chunk_num = int(chunk_num_string)

        value = ""
        for i in range(chunk_num):
            uid_i = path_join(uid, str(i))
            res = self.storage_server.get(uid_i)

            if not res:
                return None
            else:
                cipher_all_string = res[7:]
                try:
                    IV, cipher_value, old_tag = util.from_json_string(cipher_all_string)
                except:
                    raise IntegrityError()

                new_tag = self.crypto.message_authentication_code(IV + cipher_value, ka, "MD5")

                if old_tag != new_tag:
                    raise IntegrityError()
                else:
                    value += self.crypto.symmetric_decrypt(cipher_value, ke, "AES", "CBC", IV)
        
        return value

    def make_bridge(self, user, cipher_fname):
        interface_id = path_join(user, cipher_fname)
        sharer_id = path_join(self.username, cipher_fname)
        self.storage_server.put(interface_id, "[POINTER] " + sharer_id)
        return interface_id

    def get_owner_and_encrypted_original_filename(self, filename):
        k = self.get_unique_symmetric_key()
        cipher_filename = self.crypto.message_authentication_code(filename, k, "MD5")
        half = int(len(cipher_filename)/2)
        cipher_filename = cipher_filename[:half]
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
            share_list_string = self.check_integrity_and_get_value(ka, share_id)
            share_list = util.from_json_string(share_list_string)
            share_list.append(user)

        share_list_string = util.to_json_string(share_list)
        self.MAC_and_store(share_list_string, ka, share_id)

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
            encrypted_newfilename = self.crypto.message_authentication_code(newname, k, "MD5")
            half = int(len(encrypted_newfilename)/2)
            encrypted_newfilename = encrypted_newfilename[:half]
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
        cipher_name = self.crypto.message_authentication_code(name, k, "MD5")
        half = int(len(cipher_name)/2)
        cipher_name = cipher_name[:half]
        interface_id = path_join(user, cipher_name)
        self.storage_server.delete(interface_id)

        new_keys = self.re_encrypt_file(name)
        new_ka, new_ke = new_keys

        owner, encrypted_original_filename = self.get_owner_and_encrypted_original_filename(name)
        share_id = path_join(self.username, encrypted_original_filename, "shared_with")
        share_list_string = self.check_integrity_and_get_value(old_ka, share_id)
        share_list = util.from_json_string(share_list_string)

        if user in share_list:
            share_list.remove(user)

        self.re_distribute_keys(share_id, share_list, encrypted_original_filename, old_ka, new_keys)

    def re_encrypt_file(self, name):
        k = self.get_unique_symmetric_key()
        encrypted_filename = self.crypto.message_authentication_code(name, k, "MD5")
        half = int(len(encrypted_filename)/2)
        encrypted_filename = encrypted_filename[:half]
        fid = self.revolve(path_join(self.username, encrypted_filename, "keys"))
        value = self.download(name)
        ka, ke = self.make_file_keys(fid)
        all_keys = (ka, ke, k)
        self.upload_helper(all_keys, name, value)
        return (ka, ke)

    def re_distribute_keys(self, share_id, share_list, encrypted_original_filename, old_ka, new_keys):
        share_list_string = util.to_json_string(share_list)
        self.MAC_and_store(share_list_string, new_keys[0], share_id)
        if share_list == None or len(share_list) == 0:
            return
        else:
            for user in share_list:
                self.share_keys_with_user(user, encrypted_original_filename, new_keys)

                user_share_id = path_join(user, encrypted_original_filename, "shared_with")
                user_share_list_string = self.check_integrity_and_get_value(old_ka, user_share_id)
                if user_share_list_string is not None:
                    user_share_list = util.from_json_string(user_share_list_string)
                    self.re_distribute_keys(user_share_id, user_share_list, encrypted_original_filename, old_ka, new_keys)

class MerkleTree:
    
    class Node:

        def __init__(self, hash_value, left, right, chunk_index):
            self.hash_value = hash_value
            self.left = left
            self.right = right
            self.chunk_index = chunk_index

        def set_label(self, label):
            self.label = label

        def get_label(self):
            return self.label

        def get_hash_value(self):
            return self.hash_value

        def get_left(self):
            return self.left

        def get_right(self):
            return self.right

        def get_chunk_index(self):
            return self.chunk_index

        def is_leaf(self):
            return not self.left and not self.right

    def __init__(self, client, string):
        self.client = client
        self.string = string

        chunk_num = int( len(string) / chunk + 1 )
        node_list = []
        for i in range(chunk_num):
            start, end = i * chunk, min(len(string), (i + 1) * chunk)
            value = string[start : end]
            hash_value = self.client.crypto.cryptographic_hash(value, 'MD5')
            node = self.Node(hash_value, None, None, i)
            node_list.append(node)

        self.root = self._construct_tree(node_list)
        self.label_nodes()

    def _construct_tree(self, node_list):
        if len(node_list) == 1:
            return node_list[0]
        else:
            new_node_list = []
            iter_num = int(len(node_list) / 2)
            for i in range(iter_num):
                left = node_list.pop(0)
                right = node_list.pop(0)
                new_value = left.get_hash_value() + right.get_hash_value()
                new_hash_value = self.client.crypto.cryptographic_hash(new_value, "MD5")
                new_node = self.Node(new_hash_value, left, right, None)
                new_node_list.append(new_node)

            if len(node_list) % 2 == 1:
                new_node_list.append(node_list[0])

            return self._construct_tree(new_node_list)

    def label_nodes(self):

        def label_nodes_helper(node):
            if node.is_leaf():
                return
            else:
                node.get_left().set_label(node.get_label() * 2 + 1)
                node.get_right().set_label(node.get_label() * 2 + 2)
                label_nodes_helper(node.get_left())
                label_nodes_helper(node.get_right())

        self.root.set_label(0)
        label_nodes_helper(self.root)

    def store_tree(self, keys, uid):

        ka, ke = keys
        client = self.client
        def store_tree_helper(node):
            if not node:
                return
            else:
                uid_label = path_join(uid, "", str(node.get_label()))
                # client.MAC_and_store(node.get_hash_value(), ka, uid_label)
                client.storage_server.put(uid_label, node.get_hash_value())  # <--
                store_tree_helper(node.get_left())
                store_tree_helper(node.get_right())

        store_tree_helper(self.root)

    def find_update_list(self, keys, uid):
        update_list = []
        ka, ke = keys
        client = self.client

        def find_update_list_helper(node, label):
            hash_value = node.get_hash_value()
            uid_label = path_join(uid, "", str(label))
            # server_value = client.check_integrity_and_get_value(ka, uid_label)
            server_value = client.storage_server.get(uid_label)
            # server_value = server_value[7:]
            if hash_value != server_value:
                if node.is_leaf():
                    update_component = (node.get_chunk_index(), uid_label, hash_value)
                    update_list.append(update_component)
                else:
                    label_left = label * 2 + 1
                    label_right = label * 2 + 2
                    find_update_list_helper(node.get_left(), label_left)
                    find_update_list_helper(node.get_right(), label_right)

        find_update_list_helper(self.root, self.root.get_label())
        return update_list

    def update(self, keys, uid):
        update_list = self.find_update_list(keys, uid)
        ka, ke = keys
        for chunk_index, uid_label, hash_value in update_list:
            uid_i = path_join(uid, str(chunk_index))
            start, end = chunk_index * chunk, min(len(self.string), (chunk_index + 1) * chunk)
            new_value = self.string[start : end]
            self.client.AES_CBC_and_store(new_value, keys, uid_i)
            # self.client.MAC_and_store(hash_value, ka, uid_label)
            self.client.storage_server.put(uid_label, hash_value)  # <--
