from dataclasses import dataclass
from typing import List, Union



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


# the first output will go to our 2nd wallet
out1_pkb_hash = PublicKey.from_point(public_key2).encode(compressed=True, hash160=True)
out1_script = Script([118, 169, out1_pkb_hash, 136, 172]) # OP_DUP, OP_HASH160, <hash>, OP_EQUALVERIFY, OP_CHECKSIG
print(out1_script.encode().hex())

# the second output will go back to us
out2_pkb_hash = PublicKey.from_point(public_key).encode(compressed=True, hash160=True)
out2_script = Script([118, 169, out2_pkb_hash, 136, 172])
print(out2_script.encode().hex())