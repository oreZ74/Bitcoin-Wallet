# !/usr/bin/env python3
import codecs
from dataclasses import dataclass

import ecdsa
import hashlib
import binascii
import base58
import struct

import pandas
def wallet():
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
        return bitcoinAddress.decode('utf8')


wallet1 = wallet()
wallet2 = wallet()

print(wallet1)
print(wallet2)

prev_txid = "038889c18594c8e044eccf57d8eca75371d9cb539432c169ced36ab6486991ee"
# outpoint = index nummer + tx id
outpoint = "9844f4682eae5bb14297a94124d09f7fd635dbb2241490c99ca2e2ec3dc821db"
Alice_adress = wallet1
Bob_adress = wallet2
Alice_private_key = "8b31e5d0b8d36a7a24cd03d277d34453222569fe96c56586705a0882273c9ac6"
decoded = base58.b58decode(Alice_adress)
hex_encoded = decoded.hex()

Alice_hashed_pubkey = base58.b58decode_check(Alice_adress)[1:].hex()
Bob_hashed_pubkey = base58.b58decode_check(Bob_adress)[1:].hex()

class raw_tx:
    version = struct.pack("<L", 1)
    tx_in_count = 0  # temp
    tx_in = {}  # temp
    tx_out_count = 0  # temp
    tx_out1 = {}  # temp
    tx_out2 = {}  # temp
    lock_time = struct.pack("<L", 0)

    hash_code = struct.pack("<L", 1)

    tx_to_sign = 0  # temp

    def flip_byte_order(self, string):  # string, not bianry!
        flipped = "".join(reversed([string[i:i + 2] for i in range(0, len(string), 2)]))
        return flipped


############################################################################

rtx = raw_tx()

rtx.tx_in_count = struct.pack("<B", 1)
rtx.tx_in["outpoint_hash"] = bytes.fromhex(rtx.flip_byte_order(outpoint))
rtx.tx_in["outpoint_index"] = struct.pack("<L", 1)
rtx.tx_in["script_byes"] = 0  # temp
rtx.tx_in["script"] = bytes.fromhex(("76a914%s88ac" % Alice_hashed_pubkey))
rtx.tx_in["script_byes"] = struct.pack("<B", (len(rtx.tx_in["script"])))
rtx.tx_in["sequence"] = b"\xffffffff"

rtx.tx_out_count = struct.pack("<B", 2)

rtx.tx_out1["value"] = struct.pack("<Q", 50000)  # send to Bob
rtx.tx_out1["pk_script_bytes"] = 0  # temp
rtx.tx_out1["pk_script"] = bytes.fromhex(("76a914%s88ac" % Bob_hashed_pubkey))
rtx.tx_out1["pk_script_bytes"] = struct.pack("<B", (len(rtx.tx_out1["pk_script"])))

rtx.tx_out2["value"] = struct.pack("<Q", 50000)  # send back (change)
rtx.tx_out2["pk_script_bytes"] = 0  # temp
rtx.tx_out2["pk_script"] = bytes.fromhex(("76a914%s88ac" % Alice_hashed_pubkey))
rtx.tx_out2["pk_script_bytes"] = struct.pack("<B", (len(rtx.tx_out1["pk_script"])))

rtx.tx_to_sign = (
        rtx.version
        + rtx.tx_in_count
        + rtx.tx_in["outpoint_hash"]
        + rtx.tx_in["outpoint_index"]
        + rtx.tx_in["script_byes"]
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
        + rtx.hash_code
)

#############################################################################

hashed_raw_tx = hashlib.sha256(hashlib.sha256(rtx.tx_to_sign).digest()).digest()

#############################################################################

sk = ecdsa.SigningKey.from_string(bytes.fromhex(Alice_private_key), curve=ecdsa.SECP256k1)

vk = sk.verifying_key
ecdsaPrivateKey = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
print(ecdsaPrivateKey.to_string().hex())
public_key ='\04' + ecdsaPrivateKey.get_verifying_key().to_string().hex()
#############################################################################

sign = sk.sign_digest(hashed_raw_tx, sigencode=ecdsa.util.sigencode_der)

#############################################################################

sigscript = (
        sign
        + b"\x01"
        + struct.pack("<B", len(bytes.fromhex(hex_encoded)))
        + bytes.fromhex(hex_encoded)
)


#############################################################################

real_tx = (
        rtx.version
        + rtx.tx_in_count
        + rtx.tx_in["outpoint_hash"]
        + rtx.tx_in["outpoint_index"]
        + struct.pack("<B", (len(sigscript) + 1))
        + struct.pack("<B", len(sign) + 1)
        + sigscript
        + rtx.tx_in["sequence"]
        + rtx.tx_out_count
        + rtx.tx_out1["value"]
        + rtx.tx_out1["pk_script"]
        + rtx.tx_out2["value"]
        + rtx.tx_out2["pk_script_bytes"]
        + rtx.tx_out2["pk_script"]
        + rtx.lock_time)

hex_tx = real_tx.hex()

print("TX Hash: ")
print(hex_tx)