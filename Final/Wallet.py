import ecdsa
import base58
import hashlib
import binascii

class Wallet(object):
    def init(self):
        self.ecdsaPrivateKey = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        #print("ECDSA PrivatKey:\n", self.ecdsaPrivateKey.to_string().hex())
        self.ecdsaPublicKey = '04' + self.ecdsaPrivateKey.get_verifying_key().to_string().hex()
        #print("ECDSA Public Key:\n", self.ecdsaPublicKey)

        hash256FromECDSAPublicKey = hashlib.sha256(binascii.unhexlify(self.ecdsaPublicKey)).hexdigest()
        #print("SHA256(ECDSA Public Key):\n", hash256FromECDSAPublicKey)

        ridemp160FromHash256 = hashlib.new('ripemd160', binascii.unhexlify(hash256FromECDSAPublicKey))
        #print("RIDEMP160(SHA256(ECDSA Public Key)):\n", ridemp160FromHash256.hexdigest())

        prependNetworkByte = '6f' + ridemp160FromHash256.hexdigest()
        #print("Prepend Network Byte to RIDEMP160(SHA256(ECDSA Public Key)):\n", prependNetworkByte)

        hash = prependNetworkByte
        for x in range(1, 3):
            hash = hashlib.sha256(binascii.unhexlify(hash)).hexdigest()
            #print("\t|>SHA256 #", x, " : ", hash)
        cheksum = hash[:8]
        appendChecksum = prependNetworkByte + cheksum
        #print("Checksum(first 4 bytes): ", cheksum)
        #print("Append Checksum to RIDEMP160(SHA256(ECDSA Public Key)): ", appendChecksum)

        self.bitcoinAddress = base58.b58encode(binascii.unhexlify(appendChecksum))
        #print("BITCOIN PUBLIC ADDRESS: ", self.bitcoinAddress.decode('utf8'))


w1 = Wallet()
print(f'{w1.bitcoinAddress}')
w2 = Wallet()
print(f'{w2.bitcoinAddress}')