#!/usr/bin/env python3.8

import os, sys


ROOT=os.path.split(os.path.dirname( os.path.realpath( __file__ ) ))[0]
PRIVATE_KEY=os.path.join(ROOT, "config", "decrypt_key.pem")
PUBLIC_KEY=os.path.join(ROOT, "config", "encrypt_key.pem")


print(ROOT)

if os.path.exists(PRIVATE_KEY):
	res = input("keys already exist! Do you want to replace? (type 'Y')): ")
	if res != "Y":
		print("canceled")
		sys.exit(1)

print("generating private key: {}".format(PRIVATE_KEY))
os.system('openssl genrsa -out "{}" 3072'.format(PRIVATE_KEY))

print("generating public key: {}".format(PUBLIC_KEY))
os.system('openssl rsa -in "{}" -pubout -out "{}"'.format(PRIVATE_KEY, PUBLIC_KEY))

print("done")