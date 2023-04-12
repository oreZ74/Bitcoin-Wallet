import struct
import ecdsa
import base58
import hashlib

outpoint = "9844f4682eae5bb14297a94124d09f7fd635dbb2241490c99ca2e2ec3dc821db"

Alice_adress = "1NWzVg38ggPoVGAG2VWt6ktdWMaV6S1pJK"
Alice_hashed_pubkey = base58.b58decode_check(Alice_adress)[1:].hex()

Bob_adress = "1ANRQ9bEJZcwXiw7YZ6uE5egrE7t9gCyip"
Bob_hashed_pubkey = base58.b58decode_check(Bob_adress)[1:].hex()

Alice_private_key = "91dc1da3c2f3b734b454e67c8ed54cd4d0e4a7df38a286ad627a78c5d4fc0dfc"


#############################################################################
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

signature = sk.sign_digest(hashed_raw_tx, sigencode=ecdsa.util.sigencode_der)

#############################################################################

sigScript = ((len(signature) + 1).to_bytes(1, byteorder="little", signed=False)
            + signature
            + bytes.fromhex("01")
            +(len(public_key)).to_bytes(1, byteorder="little", signed=False)
            + public_key
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

print(real_tx.encode("hex"))
