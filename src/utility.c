#include "utility.h"

const char* hash1 = "d2d3b3c385d276a68e6487859d3a82d6b966bbc5ecf0f5231e39304f8a1c26ec";
const char* hash2 = "2fcd6fb2835518528d7d1f396c2f61899be99f829eff0b0900c3e5702cb91391";
const char* vseed = "2990a761daa2249c91ae98acf56ecf558876f6aa566e1e6e025996f12c830b793d87dde3f68cf9138fbe041bb75ba500c8eadee43d3ce2c95f84f89925bf8db5";
const char* m_pubkey = "0224f058df29df85d8beefb32de09f8021a77103a16461569124a970180894b006";
const char* m_chaincode = "74708ceb460eb927b337a6bb12c5580409c7bb2b0ffa88e84f1e9d34b5d15aa9";
const char* m44_pubkey = "03257ed946188609f79a00654bed7bbdcb06b33f8fad855dcdf38903716c423fe9";
const char* m4460_pubkey = "0257be163ce02fb13f6dc098f2bf63b1d7ed617247501619618bcbdf3fcf9bcf14";
const char* m44600_pubkey = "03f0be61b961572efe595d1aa93970f57e8b2c9e438ce6bc42cc6ea3572a872bd9";
const char* m446000_pubkey = "0329b4182e9a800bc10715a5f4f1737886f45d544e03b64c162425ede654d919f8";
const char* m4460000_pubkey = "036bf7d2b891ada777a163953bae1f37c162405502b1c411338645d07b428fcf24";

void hash256(const uint8_t *data, uint8_t *output, size_t size) {

    hasher_Raw(HASHER_SHA2, data, size, output);
    // compare_keys("Unsign_txn hash1", output, hash1, SHA256_DIGEST_LENGTH);

    sha256_Raw(output, SHA256_DIGEST_LENGTH, output);
    // compare_keys("Unsign_txn hash2", output, hash2, SHA256_DIGEST_LENGTH);
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
    compare_keys("M441_pubkey", node.public_key, m441_pubkey, publickey_len);
    // node_details(node); 

    hdnode_private_ckd(&node, account);
    hdnode_fill_public_key(&node);
    compare_keys("M4410_pubkey", node.public_key, m4410_pubkey, publickey_len);
    // node_details(node); 

    hdnode_private_ckd(&node, change);
    hdnode_fill_public_key(&node);
    // compare_keys("M44100_pubkey", node.public_key, m44100_pubkey, publickey_len);
    // node_details(node); 

    hdnode_private_ckd(&node, address_idx);
    hdnode_fill_public_key(&node);
    // compare_keys("M441000_pubkey", node.public_key, m441000_pubkey, publickey_len);
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