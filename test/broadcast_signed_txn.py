
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

# Sender address
sender_address = "0x47Ea71715F8049B80eD5C20d105e9C5D7631113f"

# Recipient address
recipient_address = "0x6B61fd05FA7e73c2de6B1999A390Fee252109072"

# Gas price in Wei (replace with your own value)
gas_price = web3.to_wei("20", "gwei")

# Gas limit (replace with your own value)
gas_limit = 22000

# Value to send in Wei (replace with your own value)
value = web3.to_wei("0.05", "ether")

# Nonce (replace with your own value)
nonce = 9644607 #web3.eth.get_transaction_count(sender_address)

# Chain ID (replace with the appropriate chain ID)
chain_id = 11155111  # sepolia

# Create the transaction dictionary
transaction = {
    'to': recipient_address,
    'value': value,
    'gas': gas_limit,
    'gasPrice': gas_price,
    'nonce': nonce,
    'chainId': chain_id,
}

# Sign the transaction
signed_transaction = Account.sign_transaction(transaction, pk)

print(signed_transaction)

# Broadcast the transaction
# tx_hash = web3.eth.send_raw_transaction(signed_transaction.raw_transaction)

# print(f'Transaction sent. Transaction Hash: {tx_hash.hex()}')

# broadcasted transaction
# f86f808504a817c8008255f0946b61fd05fa7e73c2de6b1999a390fee25210907288016345785d8a0000808401546d71a06d94e5080c458ca35a9882cec6d67e18704e224888c3516199c3d3246d523a529f0c02d49b112aa210b43e5889b0fcfae11b7f229f350b391809e03aad827c0b
'''{
  "chainId": "11155111",
  "type": "LegacyTransaction",
  "valid": true,
  "hash": "0x4cb1520ac8b2cf5860b1b018317916eacab7459016e347f2525ce1af94778cde",
  "nonce": "0",
  "gasPrice": "20000000000",
  "gasLimit": "22000",
  "from": "0xbdAb7191cF5116C46dD718Ea39e12F4F5Ab721fd",
  "to": "0x6b61fd05fa7e73c2de6b1999a390fee252109072",
  "v": "01546d71",
  "r": "9c6f3f9117dc9ce2ecf07b3c304901330c1a75c4e79d0f7c41086a66b829d938",
  "s": "4a4fd7d0311dcafd53e32d5333e50a2f009958aaaaa284bf1522a33a2293e114",
  "value": "50000000000000000"
}
 Txn Hash: 0x82af47df04fa12c378384584ea86569166ec64b4f8787cf60978a3d5c5dcfa26
'''

'''
f87283932a3f8504a817c8008255f0946b61fd05fa7e73c2de6b1999a390fee25210907287b1a2bc2ec50000808401546d72a0dd6b7d0ae0473fc470d28c5dcb55574b78e212e847b0566fdbd7564f1901c139a05a92580f8f9a99dc0e359253a1dfccd13b13b2d4b08a87c6275b0736c2082483
{
  "chainId": "11155111",
  "type": "LegacyTransaction",
  "valid": true,
  "hash": "0x73bad52da719b5e659cfd0b75c23adfa14352528a9b594bdf3b5d3a5e0de9b10",
  "nonce": "9644607",
  "gasPrice": "20000000000",
  "gasLimit": "22000",
  "from": "0x47Ea71715F8049B80eD5C20d105e9C5D7631113f",
  "to": "0x6b61fd05fa7e73c2de6b1999a390fee252109072",
  "v": "01546d72",
  "r": "dd6b7d0ae0473fc470d28c5dcb55574b78e212e847b0566fdbd7564f1901c139",
  "s": "5a92580f8f9a99dc0e359253a1dfccd13b13b2d4b08a87c6275b0736c2082483",
  "value": "50000000000000000"
}
Txn Hash: 0x73bad52da719b5e659cfd0b75c23adfa14352528a9b594bdf3b5d3a5e0de9b10
'''