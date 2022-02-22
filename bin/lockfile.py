#!/usr/bin/env python3.8

from Crypto.Cipher import AES
from Crypto import Random
from hashlib import md5
import base64
import os, sys, shutil
import getpass

# key = get_random_bytes(16)
ENCRYPTED_EXT = ".locked"


AES_SALT_PREFIX = b"Salted__"

def toHex(value):
    value = toBytes(value)
    return binascii.hexlify(value).upper().decode('utf-8')

def toBase64(value):
    return toString(base64.b64encode(toBytes(value)))

def fromBase64(value):
    return base64.b64decode(value)

def hexToByteArray(value):
    return bytearray.fromhex(value)

def toString(value):
    if isinstance(value, bytes):
        value = value.decode()
    elif isinstance(value, bytearray):
        value = value.decode("utf-8")
    return value

def toBytes(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    elif isinstance(value, bytearray):
        value = bytes(value)
    return value

def encryptFile(path, password, out_path=None):
    if out_path is None:
        out_path = "{}{}".format(path, ENCRYPTED_EXT)
    with open(path, 'rb') as f:
        encryptDataToFile(f.read(), out_path, password)
    return out_path

def encryptDataToFile(data, out_path, password):
    data_len = len(data)
    with open(out_path, 'wb') as f:
        dlen = toBytes("{:0>32}".format(len(data)))
        edata = aes_simple_encrypt(dlen + toBytes(data), password)
        f.write(toBytes(edata))
    return out_path

def decryptFile(path, password, out_path=None):
    if out_path is None:
        out_path = path[:-1*len(ENCRYPTED_EXT)]
    with open(path, 'rb') as f:
        try:
            data = aes_simple_decrypt(f.read(), password)
        except:
            return None
    new_len = len(data) - 32
    try:
        data_len = int(data[:32])
    except:
        return None
    if new_len != data_len:
        return None
    with open(out_path, 'w') as fout:
        fout.write(toString(data[32:]))
    return out_path

def help():
    print("lockfile [] path")
    print(("\tif path ends with '{}' it will be unlocked".format(ENCRYPTED_EXT)))
    print(("\totherwise the path will be encrypted and a .{} will be created".format(ENCRYPTED_EXT)))
    print("\t-p\tpassphrase")
    print("\t-d\tdelete file when done")

def getPassword():
    # return raw_input("enter password: ")
    try:
        return getpass.getpass()
    except:
        pass
    sys.exit(1)

def doDecrypt(path, password, remove=False):
    print(("decrypting file: '{}'".format(path)))
    out_path = None
    while out_path is None:
        if password is None:
            password = getPassword()
        out_path = decryptFile(path, password)
        password = None
        if out_path is None:
            print("\ndecrypt failed")
            print("try again...")
            continue
        print("file is now unlocked")
        print("do you want to delete the old locked file?")
        # out = raw_input("press [Y] to delete, any password to continue")
        if remove:
            os.remove(path)
            if not os.path.exists(path):
                print("file removed")

def doEncrypt(path, password, remove=False):
    print(("encrypting file: '{}'".format(path)))
    if password is None:
        password = getPassword()
    out_path = encryptFile(path, password)
    print("file is now locked")
    print("do you want to delete the unlocked file?")
    # out = raw_input("press [Y] to delete, any password to continue")
    if remove:
        os.remove(path)
        if not os.path.exists(path):
            print("file removed")

def main():
    unlock = False
    path = None
    password = None
    argl = len(sys.argv)
    pos = 1
    remove = False
    while pos < argl:
        arg = sys.argv[pos]
        pos += 1
        if arg in ["-u", "--unclock"]:
            unlock = True
        elif arg in ["-k", "--key", "-p", "--pass","--password"]:
            password = sys.argv[pos]
            pos += 1
        elif arg in ["-r", "--remove", "-d", "--delete"]:
            remove = True
        elif arg.startswith('-'):
            print(("unknown option: {}".format(arg)))
        elif path is None:
            path = arg
        else:
            print(("unknown option: {}".format(arg)))
    if path is None:
        help()
        sys.exit(0)
    if unlock or path.endswith(ENCRYPTED_EXT):
        doDecrypt(path, password, remove)
    else:
        doEncrypt(path, password, remove)

# BEGIN SIMPLE AES ENCRYPTION
# THIS WORKS WITH CryptoJS Library
def pad(data, block_size=16):
    length = block_size - (len(data) % block_size)
    return data + (chr(length)*length).encode()

def unpad(data):
    return data[:-(data[-1] if type(data[-1]) == int else ord(data[-1]))]

def bytes_to_key(data, salt, output=48):
    # extended from https://gist.github.com/gsakkis/4546068
    assert len(salt) == 8, len(salt)
    data += bytes(salt)
    key = md5(data).digest()
    final_key = key
    while len(final_key) < output:
        key = md5(key + data).digest()
        final_key += key
    return final_key[:output]

def aes_simple_encrypt(message, passphrase, format="b64"):
    # format: b64, hex, bytes
    if isinstance(message, dict) or isinstance(message, list):
        message = json.dumps(message)
    message = toBytes(message)
    passphrase = toBytes(passphrase)
    salt = Random.new().read(8)
    key_iv = bytes_to_key(passphrase, salt, 32 + 16)
    key = key_iv[:32]
    iv = key_iv[32:]
    aes = AES.new(key, AES.MODE_CBC, iv)
    enc_data = AES_SALT_PREFIX + salt + aes.encrypt(pad(message))
    if format == "b64":
        return toBase64(enc_data)
    elif format == "hex":
        return toHex(enc_data)
    return enc_data


def aes_simple_decrypt(encrypted, passphrase):
    # because some are b64 and others are not we check
    b64_encoded = not (isinstance(encrypted, (bytes, bytearray)) and encrypted.startswith(AES_SALT_PREFIX))
    if b64_encoded:
        encrypted = base64.b64decode(encrypted)
    assert encrypted.startswith(AES_SALT_PREFIX)

    passphrase = toBytes(passphrase)
    salt = encrypted[8:16]
    key_iv = bytes_to_key(passphrase, salt, 32 + 16)
    key = key_iv[:32]
    iv = key_iv[32:]
    aes = AES.new(key, AES.MODE_CBC, iv)
    return unpad(aes.decrypt(encrypted[16:]))


if __name__ == '__main__':
    main()



