from eth_utils import to_hex
from ethereum.transactions import Transaction

def encode_ethereum_transaction(recipient_address, value, gas_limit, gas_price, nonce):
    transaction = Transaction(
        to=recipient_address,
        value=value,
        startgas=gas_limit,
        gasprice=gas_price,
        nonce=nonce,
        data="0x80",
    )
    serialized_transaction = transaction.serialize()
    return to_hex(serialized_transaction)

# Example usage
recipient_address = "0x6B61fd05FA7e73c2de6B1999A390Fee252109072"
value = 100000000000000000  # 0.1 ETH in Wei
gas_limit = 22000
gas_price = 20000000000  # 20 Gwei
nonce = 9644607 
chain_id = 11155111  # sepolia

encoded_transaction = encode_ethereum_transaction(
    recipient_address, value, gas_limit, gas_price, nonce
)

print(encoded_transaction)
