from __future__ import annotations  # PEP 563: Postponed Evaluation of Annotations
from dataclasses import dataclass  # https://docs.python.org/3/library/dataclasses.html I like these a lot

from base58 import b58encode
from typing import List, Union

import ecdsa
import hashlib
import binascii
import base58


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


@dataclass
class TxIn:
    prev_tx: bytes  # prev transaction ID: hash256 of prev tx contents
    prev_index: int  # UTXO output index in the transaction
    script_sig: Script = None  # unlocking script, Script class coming a bit later below
    sequence: int = 0xffffffff  # originally intended for "high frequency trades", with locktime


tx_in = TxIn(
    prev_tx=bytes.fromhex('46325085c89fb98a4b7ceee44eac9b955f09e1ddc86d8dad3dfdcba46b4d36b2'),
    prev_index=1,
    script_sig=None,  # this field will have the digital signature, to be inserted later
)


@dataclass
class TxOut:
    amount: int  # in units of satoshi (1e-8 of a bitcoin)
    script_pubkey: Script = None  # locking script


tx_out1 = TxOut(
    amount=50000  # we will send this 50,000 sat to our target wallet
)
tx_out2 = TxOut(
    amount=47500  # back to us
)


# the fee of 2500 does not need to be manually specified, the miner will claim it

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
        raise ValueError("integer too large: %d" % (i,))


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
                assert length < 75  # any longer than this requires a bit of tedious handling that we'll skip here
                out += [encode_int(length, 1), cmd]

        ret = b''.join(out)
        return encode_varint(len(ret)) + ret


# the first output will go to our 2nd wallet
#out1_pkb_hash = PublicKey.from_point(public_key2).encode(compressed=True, hash160=True)

out1_script = Script([118, 169, ecdsaPublicKey, 136, 172])  # OP_DUP, OP_HASH160, <hash>, OP_EQUALVERIFY, OP_CHECKSIG
print(out1_script.encode().hex())

# the second output will go back to us
#out2_pkb_hash = PublicKey.from_point(public_key).encode(compressed=True, hash160=True)
out2_script = Script([118, 169, ecdsaPublicKey, 136, 172])
print(out2_script.encode().hex())

tx_out1.script_pubkey = out1_script
tx_out2.script_pubkey = out2_script


@dataclass
class Tx:
    version: int
    tx_ins: List[TxIn]
    tx_outs: List[TxOut]
    locktime: int = 0

    def encode(self, sig_index=-1) -> bytes:
        """
        Encode this transaction as bytes.
        If sig_index is given then return the modified transaction
        encoding of this tx with respect to the single input index.
        This result then constitutes the "message" that gets signed
        by the aspiring transactor of this input.
        """
        out = []
        # encode metadata
        out += [encode_int(self.version, 4)]
        # encode inputs
        out += [encode_varint(len(self.tx_ins))]
        if sig_index == -1:
            # we are just serializing a fully formed transaction
            out += [tx_in.encode() for tx_in in self.tx_ins]
        else:
            # used when crafting digital signature for a specific input index
            out += [tx_in.encode(script_override=(sig_index == i))
                    for i, tx_in in enumerate(self.tx_ins)]
        # encode outputs
        out += [encode_varint(len(self.tx_outs))]
        out += [tx_out.encode() for tx_out in self.tx_outs]
        # encode... other metadata
        out += [encode_int(self.locktime, 4)]
        out += [encode_int(1, 4) if sig_index != -1 else b'']  # 1 = SIGHASH_ALL
        return b''.join(out)


# we also need to know how to encode TxIn. This is just serialization protocol.
def txin_encode(self, script_override=None):
    out = []
    out += [self.prev_tx[::-1]]  # little endian vs big endian encodings... sigh
    out += [encode_int(self.prev_index, 4)]

    if script_override is None:
        # None = just use the actual script
        out += [self.script_sig.encode()]
    elif script_override is True:
        # True = override the script with the script_pubkey of the associated input
        out += [self.prev_tx_script_pubkey.encode()]
    elif script_override is False:
        # False = override with an empty script
        out += [Script([]).encode()]
    else:
        raise ValueError("script_override must be one of None|True|False")

    out += [encode_int(self.sequence, 4)]
    return b''.join(out)


TxIn.encode = txin_encode  # monkey patch into the class


# and TxOut as well
def txout_encode(self):
    out = []
    out += [encode_int(self.amount, 8)]
    out += [self.script_pubkey.encode()]
    return b''.join(out)


TxOut.encode = txout_encode  # monkey patch into the class

tx = Tx(
    version=1,
    tx_ins=[tx_in],
    tx_outs=[tx_out1, tx_out2],
)

source_script = Script([118, 169, out2_pkb_hash, 136, 172])  # OP_DUP, OP_HASH160, <hash>, OP_EQUALVERIFY, OP_CHECKSIG
print("recall out2_pkb_hash is just raw bytes of the hash of public_key: ", out2_pkb_hash.hex())
print(source_script.encode().hex())  # we can get the bytes of the script_pubkey now

# monkey patch this into the input of the transaction we are trying sign and construct
tx_in.prev_tx_script_pubkey = source_script

# get the "message" we need to digitally sign!!
message = tx.encode(sig_index=0)
message.hex()


@dataclass
class Signature:
    r: int
    s: int


def sign(secret_key: int, message: bytes) -> Signature:
    # the order of the elliptic curve used in bitcoin
    n = bitcoin_gen.n

    # double hash the message and convert to integer
    z = int.from_bytes(hashlib.sha256(hashlib.sha256(message)), 'big')

    # generate a new secret/public key pair at random
    sk = random.randrange(1, n)
    P = sk * bitcoin_gen.G

    # calculate the signature
    r = P.x
    s = inv(sk, n) * (z + secret_key * r) % n
    if s > n / 2:
        s = n - s

    sig = Signature(r, s)
    return sig


def verify(public_key: Point, message: bytes, sig: Signature) -> bool:
    # just a stub for reference on how a signature would be verified in terms of the API
    # we don't need to verify any signatures to craft a transaction, but we would if we were mining
    pass


random.seed(int.from_bytes(sha256(message), 'big'))  # see note below
sig = sign(secret_key, message)
sig


def signature_encode(self) -> bytes:
    """ return the DER encoding of this signature """

    def dern(n):
        nb = n.to_bytes(32, byteorder='big')
        nb = nb.lstrip(b'\x00')  # strip leading zeros
        nb = (b'\x00' if nb[0] >= 0x80 else b'') + nb  # preprend 0x00 if first byte >= 0x80
        return nb

    rb = dern(self.r)
    sb = dern(self.s)
    content = b''.join([bytes([0x02, len(rb)]), rb, bytes([0x02, len(sb)]), sb])
    frame = b''.join([bytes([0x30, len(content)]), content])
    return frame


Signature.encode = signature_encode  # monkey patch into the class
sig_bytes = sig.encode()
sig_bytes.hex()

# Append 1 (= SIGHASH_ALL), indicating this DER signature we created encoded "ALL" of the tx (by far most common)
sig_bytes_and_type = sig_bytes + b'\x01'

# Encode the public key into bytes. Notice we use hash160=False so we are revealing the full public key to Blockchain
pubkey_bytes = PublicKey.from_point(public_key).encode(compressed=True, hash160=False)

# Create a lightweight Script that just encodes those two things!
script_sig = Script([sig_bytes_and_type, pubkey_bytes])
tx_in.script_sig = script_sig

tx

tx.encode().hex()

print("Transaction size in bytes: ", len(tx.encode()))


def tx_id(self) -> str:
    return sha256(sha256(self.encode()))[::-1].hex()  # little/big endian conventions require byte order swap


Tx.id = tx_id  # monkey patch into the class

tx.id()  # once this transaction goes through, this will be its id

import time;

time.sleep(1.0)  # now we wait :p, for the network to execute the transaction and include it in a block
