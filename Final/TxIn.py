from dataclasses import dataclass
import Script
@dataclass
class TxIn:
    prev_tx: bytes # prev transaction ID: hash256 of prev tx contents
    prev_index: int # UTXO output index in the transaction
    script_sig: Script = None # unlocking script, Script class coming a bit later below
    sequence: int = 0xffffffff # originally intended for "high frequency trades", with locktime

tx_in = TxIn(
    prev_tx = bytes.fromhex('46325085c89fb98a4b7ceee44eac9b955f09e1ddc86d8dad3dfdcba46b4d36b2'),
    prev_index = 1,
    script_sig = None, # this field will have the digital signature, to be inserted later
)