#!/usr/bin/env python3
from dataclasses import dataclass
import struct
import ecdsa
import hashlib
import binascii
import base58
import pandas
from typing import List, Union

class Wallet (object):
	def __int__(self):
		ecdsaPrivateKey = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
		print(ecdsaPrivateKey.to_string().hex())

		print("ECDSA PrivatKey:\n", ecdsaPrivateKey.to_string().hex())
		private_key = bytes(ecdsaPrivateKey.to_string().hex(), 'utf-8')
		private_key = binascii.unhexlify(private_key)

		ecdsaPublicKey = '04' + ecdsaPrivateKey.get_verifying_key().to_string().hex()
		print("ECDSA Public Key:\n", ecdsaPublicKey)

		hash256FromECDSAPublicKey = hashlib.sha256(binascii.unhexlify(ecdsaPublicKey)).hexdigest()
		print("SHA256(ECDSA Public Key):\n", hash256FromECDSAPublicKey)

		ridemp160FromHash256 = hashlib.new('ripemd160', binascii.unhexlify(hash256FromECDSAPublicKey))
		print("RIDEMP160(SHA256(ECDSA Public Key)):\n", ridemp160FromHash256.hexdigest())
		self.hashed_pubkey = ridemp160FromHash256
		prependNetworkByte = '6f' + ridemp160FromHash256.hexdigest()
		print("Prepend Network Byte to RIDEMP160(SHA256(ECDSA Public Key)):\n", prependNetworkByte)

		hash = prependNetworkByte
		for x in range(1, 3):
			hash = hashlib.sha256(binascii.unhexlify(hash)).hexdigest()
		# print("\t|>SHA256 #", x, " : ", hash)
		cheksum = hash[:8]
		appendChecksum = prependNetworkByte + cheksum
		# print("Checksum(first 4 bytes): ", cheksum)
		# print("Append Checksum to RIDEMP160(SHA256(ECDSA Public Key)): ", appendChecksum)

		self.bitcoinAddress = base58.b58encode(binascii.unhexlify(appendChecksum))
		# print("BITCOIN PUBLIC ADDRESS: ", self.bitcoinAddress.decode('utf8'))#

 		# print(len(ridemp160FromHash256.hexdigest()))
		# print(ridemp160FromHash256.hexdigest())

		# out1_pkb_hash = ridemp160FromHash256.hexdigest()

		your_btc_address = self.bitcoinAddress.decode('utf8')
		transactions_url = 'https://blockchain.info/rawaddr/' + your_btc_address
		df = pandas.read_json(transactions_url)
		transactions = df['txs']
		print(transactions)
		self.prv_txid = transactions

def main():
	wallet1 = Wallet()
	wallet2 = Wallet()
	print(wallet1.prependNetworkByte)
	print(wallet2.prependNetworkByte)

class raw_tx:
	version 		= struct.pack("<L", 1)
	tx_in_count 	= struct.pack("<B", 1)
	tx_in 			= {} #TEMP
	tx_out_count	= struct.pack("<B", 2)
	tx_out1			= {} #TEMP
	tx_out2 		= {} #TEMP
	lock_time 		= struct.pack("<L", 0)

def flip_byte_order(string):
	flipped = "".join(reversed([string[i:i+2] for i in range(0, len(string), 2)]))
	return flipped

wallet1 = Wallet()
wallet2 = Wallet()
rtx = raw_tx()
prv_txid = "d83c0a8ca310e2b54a35733819d98118c6980b1d465b5a5a5a2673d08f80edf5"
rtx.tx_in["txouthash"] 		= flip_byte_order(prv_txid)
rtx.tx_in["tx_out_index"] 	= struct.pack("<L", 0)
rtx.tx_in["script"] 		= ("76a914%s88ac" % wallet1.hashed_pubkey).decode("hex")
rtx.tx_in["scrip_bytes"] 	= struct.pack("<B", len(rtx.tx_in["script"]))
rtx.tx_in["sequence"]		= "ffffffff".decode("hex")

rtx.tx_out1["value"]		= struct.pack("<Q", 100000)
rtx.tx_out1["pk_script"] 	= ("76a914%s88ac" % wallet1.hashed_pubkey).decode("hex")
rtx.tx_out1["pk_script_bytes"] = struct.pack("<B", len(rtx.tx_out1["pk_script"]))

rtx.tx_out2["value"]		= struct.pack("<Q", 50000)
rtx.tx_out2["pk_script"] 	= ("76a914%s88ac" % wallet1.hashed_pubkey).decode("hex")
rtx.tx_out2["pk_script_bytes"] = struct.pack("<B", len(rtx.tx_out2["pk_script"]))

raw_tx_string = (

	rtx.version
	+ rtx.tx_in_count
	+ rtx.tx_in["txouthash"]
	+ rtx.tx_in["tx_out_index"]
	+ rtx.tx_in["scrip_bytes"]
	+ rtx.tx_in["script"]
	+ rtx.tx_in["sequence"]
	+ rtx.tx_out_count
	+ rtx.tx_out1["value"]
	+ rtx.tx_out1["pk_script_bytes"]
	+ rtx.tx_out1["pk_script"]
	+ rtx.tx_out2["value"]
	+ rtx.tx_out2["pk_script_bytes"]
	+ rtx.tx_out2["pk_script"]
	+ rtx.lock_time
	+ struct.pack("<L", 1)

	)

hashed_tx_to_sign = hashlib.sha256(hashlib.sha256(raw_tx_string).digest()).digest()

sk = ecdsa.SigningKey.from_string(Bob_private_key.decode("hex"), curve = ecdsa.SECP256k1)

vk = sk.verifying_key

public_key = ('\04' + vk.to_string()).encode("hex")

signature = sk.sign_digest(hashed_tx_to_sign, sigencode = ecdsa.util.sigencode_der_canonize)

sigscript = (

	signature
	+ "\01"
	+ struct.pack("<B", len(public_key.decode("hex")))
	+ public_key.decode("hex")

	)

real_tx = (
	rtx.version
	+ rtx.tx_in_count
	+ rtx.tx_in["txouthash"]
	+ rtx.tx_in["tx_out_index"]
	+ struct.pack("<B", len(sigscript) + 1)
	+ struct.pack("<B", len(signature) + 1)
	+ sigscript
	+ rtx.tx_in["sequence"]
	+ rtx.tx_out_count
	+ rtx.tx_out1["value"]
	+ rtx.tx_out1["pk_script_bytes"]
	+ rtx.tx_out1["pk_script"]
	+ rtx.tx_out2["value"]
	+ rtx.tx_out2["pk_script_bytes"]
	+ rtx.tx_out2["pk_script"]
	+ rtx.lock_time

	)

print(real_tx.encode("hex"))

if __name__ == '__main__':
    main()