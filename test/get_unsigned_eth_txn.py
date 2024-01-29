
api = '1KZW6KKJCDNKURT7DS3UQJYCIC3YBWZSZG'
i_api = 'https://sepolia.infura.io/v3/af91f7d6b2d6491299b2920958fcd06d'
hash = 'e3f047354e5a1fafef1d6dce088eb97a49118cdd68a0a60ea7cfaa63b44a6c37'
pk = 'ea7308b05a2dfc9be67f4f04cbb3d6337d8b0d6c25dfc8925a05d892423c5af3'

from web3 import Web3
from eth_account import Account

# Connect to the Ethereum node
web3 = Web3(Web3.HTTPProvider(i_api))

# Get the transaction details
transaction = web3.eth.get_transaction(hash)

# Print the raw transaction hex
# raw_transaction_hex = web3.eth.account. encode_transaction(transaction).hex()
# print("Raw Transaction Hex:", raw_transaction_hex)

from pprint import pprint
pprint(transaction)

# # Encode the transaction
# encoded_transaction = Account.sign_transaction(transaction, private_key=pk)

# # # Print the raw unsigned transaction hex
# raw_transaction_hex = encoded_transaction.rawTransaction.hex()
# print("Raw Unsigned Transaction Hex:", raw_transaction_hex)

