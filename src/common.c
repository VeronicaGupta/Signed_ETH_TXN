
#include "common.h"

uint8_t* hexToUint8(const char *hexString) {
    size_t length = strlen(hexString);
    if (length % 2 != 0) {
        fprintf(stderr, "Error: Hex string must have an even number of characters.\n");
        exit(EXIT_FAILURE);
    }

    // Allocate memory for the resulting uint8_t array
    uint8_t* bytearray = (uint8_t*)malloc(length / 2);

    for (size_t i = 0; i < length; i += 2) {
        sscanf(hexString + i, "%2hhx", &bytearray[i / 2]);
    }
    return bytearray;
}

void uint8ToHexString(const uint8_t *data, size_t size, char* hexstring) {
    for (size_t i = 0; i < size; ++i) {
        for (size_t i = 0; i < size; ++i) {
            sprintf(hexstring + 2 * i, "%02x", data[i]);  // Each byte represented by 2 characters + '\0'
        }
    }
    hexstring[size * 2] = '\0'; // Null-terminate the string
}

char* intToHex(int value) {
    int num_digits = snprintf(NULL, 0, "%X", value);
    char* hex_string = (char*)malloc(num_digits + 1);
    snprintf(hex_string, num_digits + 1, "%X", value);

    return hex_string;
}

char* print_arr(char* name, uint8_t* bytearray, size_t size){
    char bytearray_hex[size*2+1];
    if (debug == true){        
        uint8ToHexString(bytearray, size, bytearray_hex);
        printf("\n%s[%d bytes]: %s\n", name, (strlen(bytearray_hex)/2), bytearray_hex);
    }
    return bytearray_hex;
}

uint8_t* print_hexarr(char* name, const char *hexString, size_t size, uint8_t* bytearray){
    if (bytearray == NULL) {
        fprintf(stderr, "Error: Memory allocation failed.\n");
        exit(EXIT_FAILURE);
    }

    memcpy(bytearray, &hexToUint8(hexString)[0], size);
    
    // print_arr(name, bytearray, size);

    return bytearray;
}