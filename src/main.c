#include "utility.h"



int main() {
    // *****************eth sepolia testnet details**********************//

    // get from bip39 (24 words) 
    const char* mnemonic = "spread sword village control response joke phrase share merit miss door canoe setup surge remind tiger increase sphere busy hand scrap diesel hair bomb";
    const char* passphrase = "";

    const int pubkey_len = 33; // uncompressed
    const int privkey_len = 32;

    uint8_t public_key[pubkey_len];
    uint8_t private_key[privkey_len];

    // Constants for HD path
    #define PURPOSE     0x8000002C  // 44
    #define COIN_TYPE   0x8000003C  // 60 Ethereum
    #define ACCOUNT     0x80000000 
    #define CHANGE      0x00000000
    #define ADDRESS_IDX 0x00000000

    get_keys(mnemonic, passphrase, public_key, private_key, pubkey_len, privkey_len, PURPOSE, COIN_TYPE, ACCOUNT, CHANGE, ADDRESS_IDX);   
    print_arr("m4460000 public key", public_key, pubkey_len); // of the input address of the unsigned txn
    print_arr("m4460000 private key", private_key, privkey_len); // of the input address of the unsigned txn

    // ***************when txn is done****************************//

    uint8_t unsigned_txn[100];
    const int unsigned_txn_len = generate_unsigned_txn(public_key, pubkey_len, unsigned_txn);
    print_arr("unsigned txn", unsigned_txn, unsigned_txn_len);

    // Calculate Keccak-256 hash of the transaction
    uint8_t unsigned_txn_hash[SHA3_256_DIGEST_LENGTH];
    hash256(unsigned_txn, unsigned_txn_hash, unsigned_txn_len);
    print_arr("unsigned txn hash", unsigned_txn_hash, SHA3_256_DIGEST_LENGTH);

    // Sign the hash with the private key
    const int sig_len = privkey_len*2;
    uint8_t sig[sig_len];
    ecdsa_sign_digest(&secp256k1, private_key, unsigned_txn_hash, sig, 0, 0);
    print_arr("sig", sig, sig_len);

    uint8_t sig_hash[32];
    hasher_Raw(HASHER_SHA2, sig, sig_len, sig_hash);
    print_arr("sig hash", sig_hash, 32);    

    // Check the signature with public key
    int result = ecdsa_verify_digest(&secp256k1, public_key,  sig, unsigned_txn_hash);
    if (result == 0) {
        printf("Transaction signing successful.\n");
    } else {
        fprintf(stderr, "Error: Transaction signing failed at %d.\n", result);
    }

    // verify signature
    // const char* verified_signature = "c515bbb14bbfcdcd3cd359c5674d71bff84ac7352057f07d3a71fbbb86f10e7263f5a826aadd3734fce97f67ec89720158f183ff94c4107a88c4162d05eeccbc";
    // compare_keys("signature", sig, verified_signature, sig_len);

    // Output the values
    uint8_t v, r[privkey_len], s[privkey_len];
    v = generate_vrs(sig, v, r, s, sig_len);
    printf("\nv[1 byte]: %02x\n", v);
    print_arr("r", r, 32);
    print_arr("s", s, 32);

    uint8_t signed_txn[300];
    generate_signed_txn(unsigned_txn, v, r, s, unsigned_txn_len, signed_txn);

    return 0;
}