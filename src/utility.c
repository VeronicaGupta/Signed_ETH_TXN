#include "utility.h"

const char* hash = "c09f99ed15627200695f2ad67b9634c86c874afc97c552305540d72cab9bf273";
const char* vseed = "2990a761daa2249c91ae98acf56ecf558876f6aa566e1e6e025996f12c830b793d87dde3f68cf9138fbe041bb75ba500c8eadee43d3ce2c95f84f89925bf8db5";
const char* m_pubkey = "036cd519b8ee267e7135b44e802df07970e56e3447bec20b720bd8fd8217b35a1d";
const char* m_chaincode = "10f33e10df2f3864bb74e671cd510804cb69b88ae570fb714b4506ccca813b5c";
const char* m44_pubkey = "03934580d6dc070772788b0c9d31c091596cd7ed06a92dcaa94d5029c83984cd7c";
const char* m4460_pubkey = "027dc18d1ef4cdac075436ccc8ed4e9811d33d82f56a4c371854b28817af57c76a";
const char* m44600_pubkey = "0298923deeecc9350aac6675e3f296bc5b37c35c34e8162c610c54ce2a6627af15";
const char* m446000_pubkey = "02ea988cd5d2bfbc11dd37a882565517aa2fa45a0c4dc4bff5cc8b727acd63a73a";
const char* m4460000_pubkey = "024eb7a0fb5db32746a28adf81a24daa5312d351c5af8ee957d04c9f443825b806";

// 6 parameters
const char* nonce = "02";//"932A3F";// "932A3F"; // 9644606+1
const char* gasPrice = "051f4d5c00"; //22 gwei
const char* gasLimit = "55F0"; // 22000
const char* toAddress = "6B61fd05FA7e73c2de6B1999A390Fee252109072";// "bbe6e5ad6bdbf22b284870493893b7c0addcb405" "47Ea71715F8049B80eD5C20d105e9C5D7631113f";
const char* valueTrans = "071afd498d0000"; // 0.002 ETH
const int chain_id = 11155111; // sepolia

uint8_t* rlp(int data_size, const char* data_hex, uint8_t* packet){
    uint8_t data[data_size];
    hexToUint8(data_hex, data);

    memzero(packet, data_size+1);

    packet[0] = 0x80 + data_size;
    memcpy(packet+1, data, data_size);

    print_arr("pkt", packet, data_size+1);

    return packet;
}

uint8_t* rlph(int data_size, uint8_t* data, uint8_t* packet){
    memzero(packet, data_size+1);

    packet[0] = 0x80 + data_size;
    memcpy(packet+1, data, data_size);

    print_arr("pkt", packet, data_size+1);

    return packet;
}

int generate_unsigned_txn(uint8_t* public_key, size_t pubkey_len, uint8_t* unsigned_txn){
    // {'accessList': [], 
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
    //     'yParity': 1}

    size_t unsigned_txn_len = 1+ (((strlen(nonce)+strlen(gasPrice)+strlen(gasLimit)+strlen(toAddress)+strlen(valueTrans))/2)+5) + 1 + 5 + 2;

    unsigned_txn[unsigned_txn_len];
    memzero(unsigned_txn, unsigned_txn_len);

    int i=0, r=0; uint8_t packet[30];
    unsigned_txn[i] = 0xc0 + unsigned_txn_len-1; // rest packet length
    i += 1;


    r = strlen(nonce)/2;
    if (r==1){
        unsigned_txn[i] = 0x02;    // nonce 1
        i += 1;
    } else {
        memcpy(unsigned_txn+i, rlp(r, nonce, packet), r+1); // nonce multi
        i += r+1; 
    } 
    
    r = strlen(gasPrice)/2;
    memcpy(unsigned_txn+i, rlp(r, gasPrice, packet), r+1); // gas price
    i += r+1; 
    
    r = strlen(gasLimit)/2;
    memcpy(unsigned_txn+i, rlp(r, gasLimit, packet), r+1); // gas limit
    i += r+1; 
    
    r = strlen(toAddress)/2;
    memcpy(unsigned_txn+i, rlp(r, toAddress, packet), r+1); // to address
    i += r+1; 
    
    r = strlen(valueTrans)/2;
    memcpy(unsigned_txn+i, rlp(r, valueTrans, packet), r+1); // value
    i += r+1;

    unsigned_txn[i] = 0x80; // data
    i += 1;

    uint32_t v = 28;//35 + (chain_id*2); // v
    unsigned_txn[i] = 0x84; i+=1;
    unsigned_txn[i] = (uint8_t)((v >> 24) & 0xFF); i+=1;
    unsigned_txn[i] = (uint8_t)((v >> 16) & 0xFF); i+=1;
    unsigned_txn[i] = (uint8_t)((v >> 8) & 0xFF); i+=1;
    unsigned_txn[i] = (uint8_t)(v & 0xFF); i+=1; 

    unsigned_txn[i] = 0x80; // r
    i += 1;

    unsigned_txn[i] = 0x80; // s
    i += 1;

    return i;
}

void hash256(uint8_t* data, uint8_t* output, size_t size) {
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

uint32_t generate_vrs(const uint8_t *sig, int rec_id, uint32_t v, uint8_t* r, uint8_t* s, size_t sig_len){
    memzero(r, sig_len/2);
    memzero(s, sig_len/2);

    v = 35 + rec_id + (chain_id*2);
    memcpy(r, sig, 32);
    memcpy(s, sig+32, 32);

    return v;
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

void generate_signed_txn(uint8_t* unsigned_txn, uint32_t v, uint8_t* r, uint8_t* s, size_t unsigned_txn_len, uint8_t* signed_txn){
    size_t packet_len = 3+(4+32+32);
    uint8_t packet[packet_len];

    memzero(packet, packet_len);

    int i=0, l=0; uint8_t out[32];
    packet[i] = 0x84; i+=1;
    packet[i] = (uint8_t)((v >> 24) & 0xFF); i+=1;
    packet[i] = (uint8_t)((v >> 16) & 0xFF); i+=1;
    packet[i] = (uint8_t)((v >> 8) & 0xFF); i+=1;
    packet[i] = (uint8_t)(v & 0xFF); i+=1; 
    l = 32; 
    memcpy(packet+i, rlph(l, r, out), l+1); // r
    i += l+1; l = 32;
    memcpy(packet+i, rlph(l, s, out), l+1); // s

    print_arr("packet", packet, packet_len);

    int unsigned_txn_data_len =  unsigned_txn_len-1 -5 -2;

    unsigned_txn_data_len = unsigned_txn_len;

    const int signed_txn_len = 1 + 1 + unsigned_txn_data_len + packet_len; // <length of length field + length field + unsigned_txn_len + packet vrs>
    signed_txn[signed_txn_len];
    memzero(signed_txn, signed_txn_len);

    i=0;
    signed_txn[i] = 0xf8; // length of length field
    i += 1;

    signed_txn[i] = unsigned_txn_data_len + packet_len; // length field
    i += 1;

    memcpy(signed_txn+i, &unsigned_txn[1], unsigned_txn_data_len);
    i += unsigned_txn_data_len;

    memcpy(signed_txn+i, packet, packet_len);

    print_arr("signed txn", signed_txn, signed_txn_len);
    printf("%d, %d, %d\n", unsigned_txn_len, packet_len, signed_txn_len);
}

// f8
// 6f
// 02
// 85 051f4d5c00
// 82 55f0
// 94 6b61fd05fa7e73c2de6b1999a390fee252109072
// 87 071afd498d0000
// 80
// 84 01546d71
// a0 fbfd7ac2fe0db0625f6c70dd15880df025a3fac62d7b39d63d073f877b855612
// a0 0b97054ac806c6cf5e2e23d08ff66c54f763d94ce85802552b429dbf325a40de

// f8
// 6f 
// 02 
// 85 051f4d5c00
// 82 55f0
// 94 6b61fd05fa7e73c2de6b1999a390fee252109072
// 87 071afd498d0000
// 80
// 84 01546d71
// a0 8a24c5d86f4cadd603f89e06fd9855e433299b674a00e87c42e305297517bda2
// a0 04be20075eec67d01010280282493fb6d8a815fff5b32d440dc8aeed4f06e9b2

// f8
// 70
// 03
// 85 0c9f71f523
// 82 6349
// 94 6b61fd05fa7e73c2de6b1999a390fee252109072
// 87 470de4df820000
// 81 80
// 84 01546d71
// a0 5676ea98bc0700961e68c2ec5d1a99cba5e423c23e2691b616f19dc7da8d849e
// a0 174ec346c4d2c02588ee73f47405da4bd39051492fb6036f8522099488e01e8b

// f8
// 70
// 03
// 85 0c9f71f523
// 82 6349
// 94 6b61fd05fa7e73c2de6b1999a390fee252109072
// 87 470de4df820000
// 81 80
// 84 01546d71
// a0 c78a06dc321d7bf2c803576d5832a352a317eeb24e7f008f17940fa86c378dfa
// a0 5582556d70f261d6aaad4abcd88e4a71a246ba05858fce4ea9a12fe18015359c

// 02 // hash function type kecceb256

// f8 // length of length field
// 7a // 122 length
// 83 aa36a7 // 11155111 chain id
// 83 932a3e // 9644606 nonce
// 85 0218711a00 // 9000000000 maxPriorityFeePerGas
// 85 1405ffdc00 // 86000000000 maxFeePerGas
// 82 55f0 // 55f0
// 94 47ea71715f8049b80ed5c20d105e9c5d7631113f // to address
// 88 06f05b59d3b20000 // 500000000000000000 value transferred
// 80 // code 
// c0 // 190
// 01 // 1 v
// a0 c515bbb14bbfcdcd3cd359c5674d71bff84ac7352057f07d3a71fbbb86f10e72 // r
// a0 63f5a826aadd3734fce97f67ec89720158f183ff94c4107a88c4162d05eeccbc // s

// (3+3+5+5+2+20+8+0+0+0+32+32)+12 = 122 (length field)

// AttributeDict({
        // 'accessList': [], 
        // 'blockHash': HexBytes('0x37232cccbd2216fa461a5e87a117b9be11fb1077b6c35ab36e7ba6b3029dd3b7'), 
        // 'blockNumber': 5120444, 
        // 'chainId': 11155111, 
        // 'from': '0x1fc35B79FB11Ea7D4532dA128DfA9Db573C51b09', 
        // 'gas': 22000, 
        // 'gasPrice': 55304412496, 
        // 'hash': HexBytes('0xe3f047354e5a1fafef1d6dce088eb97a49118cdd68a0a60ea7cfaa63b44a6c37'), 
        // 'input': HexBytes('0x'), 
        // 'maxFeePerGas': 86000000000, 
        // 'maxPriorityFeePerGas': 9000000000, 
        // 'nonce': 9644606, 
        // 'r': HexBytes('0xc515bbb14bbfcdcd3cd359c5674d71bff84ac7352057f07d3a71fbbb86f10e72'), 
        // 's': HexBytes('0x63f5a826aadd3734fce97f67ec89720158f183ff94c4107a88c4162d05eeccbc'), 
        // 'to': '0x47Ea71715F8049B80eD5C20d105e9C5D7631113f', 
        // 'transactionIndex': 237, 
        // 'type': 2, 
        // 'v': 1, 
        // 'value': 500000000000000000, 
        // 'yParity': 1
        // })

// signature = "c515bbb14bbfcdcd3cd359c5674d71bff84ac7352057f07d3a71fbbb86f10e7263f5a826aadd3734fce97f67ec89720158f183ff94c4107a88c4162d05eeccbc"