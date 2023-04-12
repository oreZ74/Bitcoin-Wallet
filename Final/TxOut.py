from dataclasses import dataclass

import Script

@dataclass
class TxOut:
    amount: int # in units of satoshi (1e-8 of a bitcoin)
    script_pubkey: Script = None # locking script

tx_out1 = TxOut(
    amount = 50000 # we will send this 50,000 sat to our target wallet
)
tx_out2 = TxOut(
    amount = 47500 # back to us
)
# the fee of 2500 does not need to be manually specified, the miner will claim it