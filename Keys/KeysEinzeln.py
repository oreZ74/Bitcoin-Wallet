
#!/usr/bin/env python3
from dataclasses import dataclass

import ecdsa
import hashlib
import binascii
import base58
from typing import List, Union
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


print("Private Key: ", ecdsaPrivateKey)
print("Private Key: ", private_key)

print(bytes.fromhex("68656c6c6f"))

hex_str = "68656c6c6f"
byte_str = bytes.fromhex(hex_str)
print(byte_str) # Ausgabe: b'hello'