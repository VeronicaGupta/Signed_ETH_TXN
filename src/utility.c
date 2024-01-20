#include "utility.h"

const char* hash = "30cce47fe62385435c30717d094e88a51b33e9f528eb071b079cbf98389995c6";
const char* vseed = "2990a761daa2249c91ae98acf56ecf558876f6aa566e1e6e025996f12c830b793d87dde3f68cf9138fbe041bb75ba500c8eadee43d3ce2c95f84f89925bf8db5";
const char* m_pubkey = "036cd519b8ee267e7135b44e802df07970e56e3447bec20b720bd8fd8217b35a1d";
const char* m_chaincode = "10f33e10df2f3864bb74e671cd510804cb69b88ae570fb714b4506ccca813b5c";
const char* m44_pubkey = "03934580d6dc070772788b0c9d31c091596cd7ed06a92dcaa94d5029c83984cd7c";
const char* m4460_pubkey = "027dc18d1ef4cdac075436ccc8ed4e9811d33d82f56a4c371854b28817af57c76a";
const char* m44600_pubkey = "0298923deeecc9350aac6675e3f296bc5b37c35c34e8162c610c54ce2a6627af15";
const char* m446000_pubkey = "02ea988cd5d2bfbc11dd37a882565517aa2fa45a0c4dc4bff5cc8b727acd63a73a";
const char* m4460000_pubkey = "024eb7a0fb5db32746a28adf81a24daa5312d351c5af8ee957d04c9f443825b806";

uint8_t* rlp(int data_size, const char* packet_hex, uint8_t* packet){
    uint8_t data[data_size];
    hexToUint8(packet_hex, data);

    memzero(packet, data_size+1);

    packet[0] = 0x80 + data_size;
    memcpy(packet+1, data, data_size);

    return packet;
}

const char* gasPrice = "000ce0665d50";
const char* gasLimit = "5208";
const char* toAddress = "47Ea71715F8049B80eD5C20d105e9C5D7631113f";
const char* valueTrans = "01c8c979daabea";

int generate_unsigned_txn(uint8_t* public_key, size_t pubkey_len, uint8_t* unsigned_txn){
    // transaction_data = {
    //     'accessList': [],
    //     'blockHash': HexBytes('0x37232cccbd2216fa461a5e87a117b9be11fb1077b6c35ab36e7ba6b3029dd3b7'),
    //     'blockNumber': 5120444,
    //     'chainId': 11155111,
    //     'from': '0x1fc35B79FB11Ea7D4532dA128DfA9Db573C51b09',
    //     'gas': 22000,
    //     'gasPrice': 55304412496,
    //     'hash': HexBytes('0xe3f047354e5a1fafef1d6dce088eb97a49118cdd68a0a60ea7cfaa63b44a6c37'),
    //     'input': HexBytes('0x'),
    //     'maxFeePerGas': 86000000000,
    //     'maxPriorityFeePerGas': 9000000000,
    //     'nonce': 9644606,
    //     'r': HexBytes('0xc515bbb14bbfcdcd3cd359c5674d71bff84ac7352057f07d3a71fbbb86f10e72'),
    //     's': HexBytes('0x63f5a826aadd3734fce97f67ec89720158f183ff94c4107a88c4162d05eeccbc'),
    //     'to': '0x47Ea71715F8049B80eD5C20d105e9C5D7631113f',
    //     'transactionIndex': 237,
    //     'type': 2,
    //     'v': 1,
    //     'value': 500000000000000000,
    //     'yParity': 1
    // }

    int unsigned_txn_len = 1 + 1 + (4 + ((strlen(gasPrice)+strlen(gasLimit)+strlen(toAddress)+strlen(valueTrans))/2)) + 1;

    unsigned_txn[unsigned_txn_len];
    memzero(unsigned_txn, unsigned_txn_len);

    int i=0, r=0; uint8_t packet[50];
    unsigned_txn[i] = unsigned_txn_len;

    i += r+1;
    unsigned_txn[i] = 0x80; // nonce

    i += r+1; r = strlen(gasPrice)/2;
    memcpy(unsigned_txn+i, rlp(r, gasPrice, packet), r+1);

    i += r+1; r = strlen(gasLimit)/2;
    memcpy(unsigned_txn+i, rlp(r,gasLimit, packet), r+1);

    i += r+1; r = strlen(toAddress)/2;
    memcpy(unsigned_txn+i, rlp(r,toAddress, packet), r+1);

    i += r+1; r = strlen(valueTrans)/2;
    memcpy(unsigned_txn+i, rlp(r,valueTrans, packet), r+1);

    i += r+1;
    unsigned_txn[i] = 0x80; // nonce

    return unsigned_txn_len;
}

void hash256(uint8_t* data, uint8_t* output, size_t size) {
    // keccak_256(data, size, output);
    hasher_Raw(HASHER_SHA3K, data, size, output);
    compare_keys("Unsign_txn hash", output, hash, SHA3_256_DIGEST_LENGTH);
}

void get_keys(const char *mnemonic, const char *passphrase, uint8_t* public_key, uint8_t* private_key,
                size_t publickey_len, size_t privkey_len, uint32_t purpose, uint32_t coin_type, 
                uint32_t account, uint32_t change, uint32_t address_idx) {
    uint8_t seed[64];
    mnemonic_to_seed(mnemonic, passphrase, seed, 0);
    compare_keys("Seed", seed, vseed, 64);

    HDNode node;
    hdnode_from_seed(seed, 64, "secp256k1", &node);
    hdnode_fill_public_key(&node);
    compare_keys("Master_pubkey", node.public_key, m_pubkey, publickey_len);
    compare_keys("Master_chaincode", node.chain_code, m_chaincode, privkey_len); 
    // node_details(node);    

    hdnode_private_ckd(&node, purpose);
    hdnode_fill_public_key(&node); 
    compare_keys("M44_pubkey", node.public_key, m44_pubkey, publickey_len);
    // node_details(node); 

    hdnode_private_ckd(&node, coin_type);
    hdnode_fill_public_key(&node);
    compare_keys("M4460_pubkey", node.public_key, m4460_pubkey, publickey_len);
    // node_details(node); 

    hdnode_private_ckd(&node, account);
    hdnode_fill_public_key(&node);
    compare_keys("M44600_pubkey", node.public_key, m44600_pubkey, publickey_len);
    // node_details(node); 

    hdnode_private_ckd(&node, change);
    hdnode_fill_public_key(&node);
    compare_keys("M446000_pubkey", node.public_key, m446000_pubkey, publickey_len);
    // node_details(node); 

    hdnode_private_ckd(&node, address_idx);
    hdnode_fill_public_key(&node);
    compare_keys("M4460000_pubkey", node.public_key, m4460000_pubkey, publickey_len);
    // node_details(node); 

    memcpy(public_key, node.public_key, publickey_len);
    memcpy(private_key, node.private_key, privkey_len);    
}
int compare_keys(char* name, uint8_t* key1, const char* key2, size_t size){
    uint8_t key2_arr[size];
    
    print_hexarr(name, key2, size, key2_arr);

    int result = memcmp(key1, key2_arr, size);
    if (result==0){
        printf("%s matched!\n", name);
    } else {
        printf("%s UNMATCHED :(\n", name);
    }
}

void node_details(HDNode node){
    printf("\nnode details: child_num[%02x] : depth[%02x]\n", node.child_num, node.depth);
}

void generate_vrs(const uint8_t *signature, uint8_t *scriptSig, uint8_t* publicKey, size_t sig_len, size_t scriptSig_len, size_t pubkey_len){
    // scriptSig: <opcode sig> <sig> <sig hash> <opcode pubkey> <pubKey>

    memzero(scriptSig, scriptSig_len);

    scriptSig[0] = sig_len+1;  // Pushdata opcode <71 bytes
    memcpy(scriptSig + 1, signature, sig_len); // Signature
    scriptSig[1 + sig_len] = 0x01;  // Sighash
    scriptSig[1 + sig_len+1] = pubkey_len;  // Pushdata opcode <71 bytes
    memcpy(scriptSig + (1 + sig_len + 2), publicKey, pubkey_len); // PublicKey

    // print_arr("scriptsig inside fn", scriptSig, scriptSig_len);
}

void prepare_final_txn(uint8_t* unsigned_txn, uint8_t* packet, uint8_t* final_txn, size_t unsigned_txn_len, size_t packet_len, size_t final_txn_len, int start_len, int end_len){
    int mid_idx = start_len+packet_len;    
    int end_idx = unsigned_txn_len-end_len;

    memzero(final_txn, final_txn_len);    

    memcpy(final_txn, unsigned_txn, start_len);
    final_txn[start_len-1] = packet_len;
    memcpy(final_txn+start_len, packet, packet_len);
    memcpy(final_txn+mid_idx, unsigned_txn+end_idx, end_len);


}

// f8

// 67
// 80
// 86 2d79883d2000
// 82
// 5208
// 94 5df9b87991262f6ba471f09758cde1c0fc1de734
// 82 7a69
// 80
// 1c
// a0 88ff6cf0fefd94db46111149ae4bfc179e9b94721fffd821d38d16464b3f71d0
// a0 45e0aff800961cfce805daef7016b9b675c137a6a41a548f7b60a3484c06a33a