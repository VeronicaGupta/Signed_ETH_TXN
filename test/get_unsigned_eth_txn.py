from ethereum.transactions import Transaction
from rlp import encode
from web3 import Web3

web3 = Web3(Web3.HTTPProvider('https://sepolia.infura.io/v3/af91f7d6b2d6491299b2920958fcd06d'))

# Sender address
sender_address = "0x47Ea71715F8049B80eD5C20d105e9C5D7631113f"
recipient_address = "0x6B61fd05FA7e73c2de6B1999A390Fee252109072"
gas_price = web3.to_wei("22", "gwei")
gas_limit = 22000
value = web3.to_wei("0.002", "ether")
nonce = web3.eth.get_transaction_count(sender_address)
chain_id = 11155111  # sepolia

# Define the transaction parameters
transaction_params = {
    'to': recipient_address,
    'value': value,
    'nonce': nonce,
    'startgas': gas_limit,
    'gasprice': gas_price,
    'data': ''
}

# Create an unsigned transaction
transaction = Transaction(**transaction_params)

# Serialize the transaction using RLP encoding
unsigned_transaction_hex = encode(transaction)

print(unsigned_transaction_hex.hex())
