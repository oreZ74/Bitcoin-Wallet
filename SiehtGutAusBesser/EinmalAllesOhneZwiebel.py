# !/usr/bin/env python3
from dataclasses import dataclass

import ecdsa
import hashlib
import binascii
import base58
import struct

import pandas

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

prependNetworkByte = '6f' + ridemp160FromHash256.hexdigest()
print("Prepend Network Byte to RIDEMP160(SHA256(ECDSA Public Key)):\n", prependNetworkByte)
print(len(ridemp160FromHash256.hexdigest()))
print(ridemp160FromHash256.hexdigest())

out1_pkb_hash = ridemp160FromHash256.hexdigest()

prv_txid = "84d813beb51c3a12cb5d0bb18c6c15062453d476de24cb2f943ca6e20115d85c"

hash = prependNetworkByte
for x in range(1, 3):
    hash = hashlib.sha256(binascii.unhexlify(hash)).hexdigest()
    print("\t|__>SHA256 #", x, " : ", hash)

cheksum = hash[:8]
appendChecksum = prependNetworkByte + cheksum
print("Checksum(first 4 bytes): ", cheksum)
print("Append Checksum to RIDEMP160(SHA256(ECDSA Public Key)): ", appendChecksum)

bitcoinAddress = base58.b58encode(binascii.unhexlify(appendChecksum))
print("BITCOIN PUBLIC ADDRESS: ", bitcoinAddress.decode('utf8'))
print("\n\n\n\n")


# your_btc_address = bitcoinAddress.decode('utf8')
# transactions_url = 'https://blockchain.info/rawaddr/' + your_btc_address
# df = pandas.read_json(transactions_url)
# transactions = df['txs']
# print(transactions)
# prv_txid = transactions


class raw_tx:
    version = struct.pack("<L", 1)
    tx_in_count = struct.pack("<B", 1)
    tx_in = {}  # TEMP
    tx_out_count = struct.pack("<B", 2)
    tx_out1 = {}  # TEMP
    tx_out2 = {}  # TEMP
    lock_time = struct.pack("<L", 0)


def flip_byte_order(string):
    flipped = "".join(reversed([string[i:i + 2] for i in range(0, len(string), 2)]))
    return flipped


rtx = raw_tx()

rtx.tx_in["txouthash"] = flip_byte_order(prv_txid)
rtx.tx_in["tx_out_index"] = struct.pack("<L", 0)
rtx.tx_in["script"] = ("76a914%s88ac" % "6f36ddb43fce23e296a92187504c76bde79f0cf377de46d669")
# rtx.tx_in["script"] 		= ("76a914%s88ac" % bob_hashed_pubkey)
rtx.tx_in["scrip_bytes"] = struct.pack("<B", len(rtx.tx_in["script"]))
rtx.tx_in["sequence"] = "ffffffff"

rtx.tx_out1["value"] = struct.pack("<Q", 100000)
rtx.tx_out1["pk_script"] = ("76a914%s88ac" % "6f36ddb43fce23e296a92187504c76bde79f0cf377de46d668")
# rtx.tx_out1["pk_script"] 	= ("76a914%s88ac" % charlie_hashed_pubkey)
rtx.tx_out1["pk_script_bytes"] = struct.pack("<B", len(rtx.tx_out1["pk_script"]))

rtx.tx_out2["value"] = struct.pack("<Q", 50000)
rtx.tx_out2["pk_script"] = ("76a914%s88ac" % "6f36ddb43fce23e296a92187504c76bde79f0cf377de46d669")
# rtx.tx_out2["pk_script"] 	= ("76a914%s88ac" % bob_hashed_pubkey)
rtx.tx_out2["pk_script_bytes"] = struct.pack("<B", len(rtx.tx_out2["pk_script"]))

raw_tx_string = (

        rtx.version
        + rtx.tx_in_count
        + rtx.tx_in["txouthash"].encode('utf-8')
        + rtx.tx_in["tx_out_index"]
        + rtx.tx_in["scrip_bytes"]
        + rtx.tx_in["script"].encode('utf-8')
        + rtx.tx_in["sequence"].encode('utf-8')
        + rtx.tx_out_count
        + rtx.tx_out1["value"]
        + rtx.tx_out1["pk_script_bytes"]
        + rtx.tx_out1["pk_script"].encode('utf-8')
        + rtx.tx_out2["value"]
        + rtx.tx_out2["pk_script_bytes"]
        + rtx.tx_out2["pk_script"].encode('utf-8')
        + rtx.lock_time
        + struct.pack("<L", 1)

)

hashed_tx_to_sign = hashlib.sha256(hashlib.sha256(raw_tx_string).digest()).digest()

sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)

vk = sk.verifying_key

public_key = ('\04' + vk.to_string()).decode('utf-8')

signature = sk.sign_digest(hashed_tx_to_sign, sigencode=ecdsa.util.sigencode_der_canonize)

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

print("Print", real_tx.encode("hex"))
print(bytes.fromhex("g2131"))