# Sign & Broadcast ETH TXN Locally

## Dependency
Add trezor-crypto library in include folder

## Execute
valgrind ./run.sh --leak-check=full

## Trezor-crypt library changes
For 'trezor-firmware' (branch release/23.12). Add below in rand.c:

### Add below in rand.h:

#define USE_INSECURE_PRNG

### Add below in address.h:
#define USE_ETHEREUM true