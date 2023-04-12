# p2pkh
import codecs
import struct

import base58


def flip_byte_order(string):
    flipped = "".join(reversed([string[i:i + 2] for i in range(0, len(string), 2)]))
    return flipped
outpoint = "9844f4682eae5bb14297a94124d09f7fd635dbb2241490c99ca2e2ec3dc821db"

Alice_adress 		= "1NWzVg38ggPoVGAG2VWt6ktdWMaV6S1pJK"
Alice_hashed_pubkey = base58.b58decode_check(Alice_adress)[1:].encode("hex")


Bob_adress	 		= "1ANRQ9bEJZcwXiw7YZ6uE5egrE7t9gCyip"
Bob_hashed_pubkey	= base58.b58decode_check(Bob_adress)[1:].encode("hex")


Alice_private_key	= ""

prv_tx_id = bytes.fromhex("41407428ed61e9b54b418eff662c21c7ec4b02546b32e2b378e2ae3bf0b3ab8f")

Bob_addr = "1NWzVg38ggPoVGAG2VWt6ktdWMaV6S1pJK"
bob_hashed_pubkey = base58.b58decode_check(Bob_addr)[1:].encode("hex")

version = (1).to_bytes(4, byteorder="little", signed=False)

tx_in_count = (1).to_bytes(1, byteorder="little", signed=False)

tx_in = "soon!"


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
rtx.tx_in["outpoint_hash"] = rtx.flip_byte_order(outpoint).decode("hex")
rtx.tx_in["outpoint_index"] = struct.pack("<L", 1)
rtx.tx_in["script_byes"] = 0  # temp
rtx.tx_in["script"] = ("76a914%s88ac" % Alice_hashed_pubkey).decode("hex")
rtx.tx_in["script_byes"] = struct.pack("<B", (len(rtx.tx_in["script"])))
rtx.tx_in["sequence"] = "ffffffff".decode("hex")

rtx.tx_out_count = struct.pack("<B", 2)

rtx.tx_out1["value"] = struct.pack("<Q", 50000)  # send to Bob
rtx.tx_out1["pk_script_bytes"] = 0  # temp
rtx.tx_out1["pk_script"] = ("76a914%s88ac" % Bob_hashed_pubkey).decode("hex")
rtx.tx_out1["pk_script_bytes"] = struct.pack("<B", (len(rtx.tx_out1["pk_script"])))

rtx.tx_out2["value"] = struct.pack("<Q", 50000)  # send back (change)
rtx.tx_out2["pk_script_bytes"] = 0  # temp
rtx.tx_out2["pk_script"] = ("76a914%s88ac" % Alice_hashed_pubkey).decode("hex")
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

tx_out_count = (1).to_bytes(1, byteorder="little", signed=False)

tx_out = "soon!"

lock_time = (0).to_bytes(4, byteorder="little", signed=False)

tx_out_value = (299000000).to_bytes(8, byteorder="little", signed=True)

tx_out_pubScript = bytes.fromhex("76a91431726579c6ab17fe2f85e236309d4c0bcff2805588ac")
tx_out_pubScript_size = bytes.fromhex("19")
print()

reversed_prv_tx_id = bytearray(prv_tx_id)

reversed_prv_tx_id.reverse()

index = (2).to_bytes(4, byteorder="little", signed=False)

sigScript_raw = bytes.fromhex("76a91486501b046d9c67aa1e361cbf49cfc6482fd16d1b88ac")

sigScript_raw_size = bytes.fromhex("19")

sequence = bytes.fromhex("ffffffff")

raw_tx = (version
          + tx_in_count
          + reversed_prv_tx_id
          + index
          + sigScript_raw_size
          + sigScript_raw
          + sequence
          + tx_out_count
          + tx_out_value
          + tx_out_pubScript_size
          + tx_out_pubScript
          + lock_time

          + (1).to_bytes(4, byteorder="little", signed=False)  # hash code
          )

print(raw_tx.hex())

import hashlib

hash_1 = hashlib.sha256(raw_tx).digest()

hash_2 = hashlib.sha256(hash_1).digest()

print(hash_2.hex())

import ecdsa

privateKey = bytes.fromhex("91dc1da3c2f3b734b454e67c8ed54cd4d0e4a7df38a286ad627a78c5d4fc0dfc")

sk = ecdsa.SigningKey.from_string(privateKey, curve=ecdsa.SECP256k1)

verifying_key = sk.get_verifying_key()

public_key = bytes.fromhex("04") + verifying_key.to_string()

signature = sk.sign_digest(hash_2, sigencode=ecdsa.util.sigencode_der_canonize)

sigScript = ((len(signature) + 1).to_bytes(1, byteorder="little", signed=False)
             + signature
             + bytes.fromhex("01")
             + (len(public_key)).to_bytes(1, byteorder="little", signed=False)
             + public_key
             )

sigScript_size = (int(len(sigScript))).to_bytes(1, byteorder="little", signed=False)

REAL_TX = (version
           + tx_in_count
           + reversed_prv_tx_id
           + index
           + sigScript_size
           + sigScript
           + sequence
           + tx_out_count
           + tx_out_value
           + tx_out_pubScript_size
           + tx_out_pubScript
           + lock_time

           )
print(REAL_TX.hex())

hash_1 = hashlib.sha256(bytes.fromhex(
    "0100000001e18e68f7fc653a9f3e249c887f03963bf5c8d10f8afc01944a1126af36e98a19060000008a4730440220113f91f8d10725b3a279cf4bd4de3d43c21d94210d22acde8f9e58c7240e884c022061b05a6ccdf8dbad5b34eb57ff6832eb2a7cb584b828bdd8ada6ec843438348d01410448d297e22dbd448f2a00501a6336c15b809df00228c527e4221338d0ce9999439e80f93a6b4c1e8281724967a62bcf44142d46dfc72d31f58b8304556f5f70aaffffffff01c060d211000000001976a91486501b046d9c67aa1e361cbf49cfc6482fd16d1b88ac00000000")).digest()

hash_2 = hashlib.sha256(hash_1).digest()

print(hash_2.hex())
