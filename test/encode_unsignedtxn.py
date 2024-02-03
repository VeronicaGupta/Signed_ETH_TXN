from eth_utils import to_hex
from ethereum.transactions import Transaction

def encode_ethereum_transaction(recipient_address, value, gas_limit, gas_price, nonce, chain_id):
    transaction = Transaction(
        to=recipient_address,
        value=value,
        startgas=gas_limit,
        gasprice=gas_price,
        nonce=nonce,
        data="0x80",
        # chain_id=chain_id,
    )
    encoded_transaction = transaction.serialize()
    return to_hex(encoded_transaction)

# Example usage
recipient_address = "0x6B61fd05FA7e73c2de6B1999A390Fee252109072"
value = 100000000000000000  # 0.1 ETH in Wei
gas_limit = 22000
gas_price = 20000000000  # 20 Gwei
nonce = 9644607 
chain_id = 11155111  # sepolia

from ethereum.transactions import Transaction
# Create the unsigned transaction object
unsigned_transaction = Transaction(
    nonce=nonce,
    gasprice=int(gas_price * 1e9),  # Convert Gwei to Wei
    startgas=gas_limit,
    to=recipient_address,
    value=int(value * 1e18),  # Convert Ether to Wei
    data=b"",
    v=chain_id * 2 + 35,  # v for EIP-155
    r=0,
    s=0,
)

# Get the hex representation of the unsigned transaction
print("Unsigned Transaction Hex:", dir(unsigned_transaction))
unsigned_transaction_hex = unsigned_transaction.hex()
print("Unsigned Transaction Hex:", unsigned_transaction_hex)
