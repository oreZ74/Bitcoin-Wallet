#!/usr/bin/env python3
from dataclasses import dataclass

import ecdsa
import hashlib
import binascii
import base58
from typing import List, Union

ecdsaPrivateKey = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
print(len(ecdsaPrivateKey.to_string().hex()))

print("ECDSA PrivatKey:\n", ecdsaPrivateKey.to_string().hex())

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


hash = prependNetworkByte
for x in range(1,3):
    hash = hashlib.sha256(binascii.unhexlify(hash)).hexdigest()
    print("\t|__>SHA256 #", x, " : ", hash)

cheksum = hash[:8]
appendChecksum = prependNetworkByte + cheksum
print("Checksum(first 4 bytes): ", cheksum)
print("Append Checksum to RIDEMP160(SHA256(ECDSA Public Key)): ", appendChecksum)

bitcoinAddress = base58.b58encode(binascii.unhexlify(appendChecksum))
print("BITCOIN PUBLIC ADDRESS: ", bitcoinAddress.decode('utf8'))
print("\n\n\n\n")

bitcoinAddress2 = base58.b58decode(bitcoinAddress)
print("BITCOIN PUBLIC ADDRESS: ", bitcoinAddress2.hex())
print("BITCOIN PUBLIC ADDRESS: ", len(bitcoinAddress2.hex()))
print("BITCOIN PUBLIC ADDRESS: ", len("12ab8dc588ca9d5787dde7eb29569da63c3a238c"))

def encode_int(i, nbytes, encoding='little'):
    """ encode integer i into nbytes bytes using a given byte ordering """
    return i.to_bytes(nbytes, encoding)

def encode_varint(i):
    """ encode a (possibly but rarely large) integer into bytes with a super simple compression scheme """
    if i < 0xfd:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' + encode_int(i, 2)
    elif i < 0x100000000:
        return b'\xfe' + encode_int(i, 4)
    elif i < 0x10000000000000000:
        return b'\xff' + encode_int(i, 8)
    else:
        raise ValueError("integer too large: %d" % (i, ))
@dataclass
class Script:
    cmds: List[Union[int, bytes]]

    def encode(self):
        out = []
        for cmd in self.cmds:
            if isinstance(cmd, int):
                # an int is just an opcode, encode as a single byte
                out += [encode_int(cmd, 1)]
            elif isinstance(cmd, bytes):
                # bytes represent an element, encode its length and then content
                length = len(cmd)
                assert length < 75 # any longer than this requires a bit of tedious handling that we'll skip here
                out += [encode_int(length, 1), cmd]

        ret = b''.join(out)
        return encode_varint(len(ret)) + ret

scriptPubKeyOut_1 = Script([118, 169, out1_pkb_hash, 136, 172])
scriptPubKeyOut_2 = Script([118, 169, out1_pkb_hash, 136, 172])

print(scriptPubKeyOut_1.encode().hex())
print(scriptPubKeyOut_2.encode().hex())

'''
Wallet 1
Wallet 2 - base58 hex - 

'''
'''
print("Bitcoin Address: ", bitcoinAddress)
base58Decoder = base58.b58decode(bitcoinAddress).hex()
print("Base58 Decoder: ", base58Decoder)

prefixAndHash = base58Decoder[:len(base58Decoder)-8]
checksum = base58Decoder[len(base58Decoder)-8:]
print("\t|___> Prefix & Hash: ", prefixAndHash)
print("\t|___> Checksum: ", checksum)
print("--------------------------------------")

hash = prefixAndHash
for x in range(1,3):
    hash = hashlib.sha256(binascii.unhexlify(hash)).hexdigest()
    print("Hash#", x, " : ", hash)
print("--------------------------------------")

if(checksum == hash[:8]):
    print("[TRUE] checksum is valid!")
else:
    print("[FALSE] checksum is not valid!")
'''

base58