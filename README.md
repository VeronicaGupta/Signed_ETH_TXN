# Sign & Broadcast ETH TXN Locally

## Dependency
Add trezor-crypto library in include folder

## Execute
valgrind ./run.sh --leak-check=full

## Broadcast Signed Txn:
https://sepolia.etherscan.io/pushTx 

## Check Current Broadcasted Signed Txn (Sepolia Testnet Legacy Ethereum Transaction)
https://sepolia.etherscan.io/tx/0x32e8803f66ccb31e5274c0d715d82fd9d62d3fbaa762dfeff3407b9051c49e3b

## Trezor-crypt library changes
For 'trezor-firmware' (branch release/23.12). Add below in rand.c:

### Add below in rand.h:

#define USE_INSECURE_PRNG

### Add below in address.h:
#define USE_ETHEREUM true