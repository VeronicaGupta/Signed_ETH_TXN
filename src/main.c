#include "utility.h"

int main() {
    // *****************btc testnet details**********************//

    // get from bip39 (btc testnet for 24 words) 
    const char* mnemonic = "spread sword village control response joke phrase share merit miss door canoe setup surge remind tiger increase sphere busy hand scrap diesel hair bomb";
    const char* passphrase = "";

    const int pubkey_len = 33; // uncompressed
    const int privkey_len = 32;

    uint8_t public_key[pubkey_len];
    uint8_t private_key[privkey_len];

    // Constants for HD path
    #define PURPOSE     0x8000002C // 44
    #define COIN_TYPE   0x8000003C  // 60 Ethereum
    #define ACCOUNT     0x80000000 
    #define CHANGE      0x00000000
    #define ADDRESS_IDX 0x00000000

    get_keys(mnemonic, passphrase, public_key, private_key, pubkey_len, privkey_len, PURPOSE, COIN_TYPE, ACCOUNT, CHANGE, ADDRESS_IDX);   
    print_arr("m4460000 public key", public_key, pubkey_len); // of the input address of the unsigned txn
    print_arr("m4460000 private key", private_key, privkey_len); // of the input address of the unsigned txn

    // ***************when txn is done****************************//

    // get unsigned_txn_hex
    // const char *unsigned_txn_hex = "0200000001b51b69ce81f857ede9791dd67cddd25f7b1690b0cf04dc4ca79f570c59cc1551010000001976a91499ccf9022fe5173d2194659687382f235169bc5788acffffffff0260ea0000000000001976a914ed614881f32c024a80d1b6b58dfed8f493f41c7288ac15a94100000000001976a914a21ba3c5f5a4f7652db388eabcbc2048f8eaa9a088ac0000000001000000";
    
    // printf("\nunsigned txn[%d bytes] : %s\n", strlen(unsigned_txn_hex)/2, unsigned_txn_hex);

    // // get unsigned txn bytearray
    // size_t unsigned_txn_len = strlen(unsigned_txn_hex) / 2;
    // uint8_t unsigned_txn[unsigned_txn_len]; 
    // print_hexarr("unsigned txn", unsigned_txn_hex, unsigned_txn_len, unsigned_txn);
    
    

    // ***************signed TXN****************************  
    // start_len = (4+1)+(il+4+1);
    // end_len = (4+1)+2*(vl+1+sl)+(4+4);
    // size_t signed_txn_len = start_len+scriptSig_len+end_len;
    // uint8_t signed_txn[signed_txn_len];
    // prepare_final_txn(unsigned_txn, scriptSig, signed_txn, unsigned_txn_len, scriptSig_len, signed_txn_len, start_len, end_len);
    
    // print_arr("unsigned txn", unsigned_txn, unsigned_txn_len);
    // print_arr("new scriptSig", scriptSig, scriptSig_len);
    // print_arr("signed txn", signed_txn, signed_txn_len);

    return 0;
}