#ifndef UTILITY_H
#define UTILITY_H

#include "common.h"

#include "trezor-crypto/sha2.h"
#include "trezor-crypto/bip39.h"
#include "trezor-crypto/bip32.h"
#include "trezor-crypto/secp256k1.h"
#include "trezor-crypto/hasher.h"
#include "trezor-crypto/memzero.h"

int generate_unsigned_txn(uint8_t* public_key, size_t pubkey_len, uint8_t* unsigned_txn);
void get_keys(const char *mnemonic, const char *passphrase, uint8_t* public_key, uint8_t* private_key,
                size_t publickey_len, size_t privkey_len, uint32_t purpose, uint32_t coin_type, 
                uint32_t account, uint32_t change, uint32_t address_idx);
                int compare_keys(char* name, uint8_t* key1, const char* key2, size_t size);
void node_details(HDNode node);
void hash256(uint8_t* data, uint8_t* output, size_t size);
int calculate_parity(const uint8_t *public_key);

uint32_t generate_vrs(const uint8_t *sig, int rec_id, uint32_t v, uint8_t* r, uint8_t* s, size_t sig_len);
void prepare_final_txn(uint8_t* unsigned_txn, uint8_t* packet, uint8_t* final_txn, size_t unsigned_txn_len, size_t packet_len, size_t final_txn_len, int start_len, int end_len);
void generate_signed_txn(uint8_t* unsigned_txn, uint32_t v, uint8_t* r, uint8_t* s, size_t unsigned_txn_len, uint8_t* signed_txn);

#endif