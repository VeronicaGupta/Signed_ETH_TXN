from ethereum import utils

private_key = bytes.fromhex('ea7308b05a2dfc9be67f4f04cbb3d6337d8b0d6c25dfc8925a05d892423c5af3')  # Replace with your private key
tx_hash = bytes.fromhex('c09f99ed15627200695f2ad67b9634c86c874afc97c552305540d72cab9bf273')  # Replace with your unsigned transaction data
unsigned_txn = bytes.fromhex('f83003850c9f71f523826349946b61fd05fa7e73c2de6b1999a390fee25210907287470de4df82000081808401546d728080')


# Sign the transaction
tx_hash = utils.keccak.Keccak_Hash(unsigned_txn, 32, True).digest()
v, r, s = utils.ecsign(tx_hash, private_key)

print(f"v: {hex(v)}")
print(f"r: {hex(r)}")
print(f"s: {hex(s)}")

# 0xf87003850c9f71f523826349946b61fd05fa7e73c2de6b1999a390fee25210907287470de4df82000081808401546d71a05676ea98bc0700961e68c2ec5d1a99cba5e423c23e2691b616f19dc7da8d849ea0174ec346c4d2c02588ee73f47405da4bd39051492fb6036f8522099488e01e8b