#ifndef __PROGTEST__
#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>
#include <memory>


#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

#endif /* __PROGTEST__ */


bool HashCheck(const uint8_t prefix[], const unsigned int prefixBitLen, const std::unique_ptr<uint8_t[]>& outputHash);

int findHash (const uint8_t prefix[], const unsigned int prefixBitLen, std::unique_ptr<uint8_t[]>& outputMessage, size_t& outputMessageLen, std::unique_ptr<uint8_t[]>& outputHash, size_t& outputHashLen, const char hashName[] = "sha256"){
     
    // TODO: Remove this condition if you are aiming for 3 points.
  

    if (prefixBitLen > 64) {
        return EXIT_FAILURE;
    }
    if(prefix == nullptr && prefixBitLen != 0) { 
        return EXIT_FAILURE;
    }    

    EVP_MD_CTX * ctx;  // struktura kontextu
    const EVP_MD * type; // typ pouzite hashovaci funkce
    unsigned char hash[EVP_MAX_MD_SIZE]; // char pole pro hash - 64 bytu (max pro sha 512)
    unsigned int length;  // vysledna delka hashe

    /* Zjisteni, jaka hashovaci funkce ma byt pouzita */
    type = EVP_get_digestbyname(hashName);

    /* Pokud predchozi prirazeni vratilo NULL, tak nebyla zadana spravne hashovaci funkce */
    if (!type) {
        return 1;
    }
    const size_t MSG_LEN = 25;

    bool found = false;
    while(!found){


        uint8_t Message_To_Hash[MSG_LEN];
        int result = RAND_bytes(Message_To_Hash, MSG_LEN);

        if(!result){
            return EXIT_FAILURE;
        }
        ctx = EVP_MD_CTX_new();
        if (ctx == nullptr) {
            EVP_MD_CTX_free(ctx);

            return EXIT_FAILURE;
        }

        if (!EVP_DigestInit_ex(ctx, type, nullptr)) {
            EVP_MD_CTX_free(ctx);

            return EXIT_FAILURE;
        }
        if (!EVP_DigestUpdate(ctx, Message_To_Hash, MSG_LEN)){
            EVP_MD_CTX_free(ctx);

            return EXIT_FAILURE;
        }
            

        if (!EVP_DigestFinal_ex(ctx, hash, &length)) {
            EVP_MD_CTX_free(ctx);

            return EXIT_FAILURE;
        }

     

        std::unique_ptr<uint8_t[]> tempHashPtr = std::make_unique<uint8_t[]>(length);
        memcpy(tempHashPtr.get(), hash, length);

        if(!HashCheck(prefix, prefixBitLen, tempHashPtr)){
            outputMessage = std::make_unique<uint8_t[]>(MSG_LEN);
            memcpy(outputMessage.get(), Message_To_Hash, MSG_LEN);
            outputMessageLen = MSG_LEN;
            outputHash = std::move(tempHashPtr);
            outputHashLen = length;
            
            found = true;
        }

        EVP_MD_CTX_free(ctx);

        if(found){
            break;
        }
    }

    return EXIT_SUCCESS;
}

bool HashCheck(const uint8_t prefix[], const unsigned int prefixBitLen, const std::unique_ptr<uint8_t[]>& outputHash) {
    for (unsigned int i = 0; i < prefixBitLen / 8; i++) {
        if (outputHash[i] != prefix[i]) return true;
    }
    if (prefixBitLen % 8) {
        uint8_t mask = 0xFF << (8 - (prefixBitLen % 8));
        if ((outputHash[prefixBitLen / 8] & mask) != (prefix[prefixBitLen / 8] & mask)) return true;
    }
    return EXIT_SUCCESS;
}
#ifndef __PROGTEST__

int checkHash(const uint8_t prefix[], const unsigned int prefixBitLen, const std::unique_ptr<uint8_t[]>& outputHash) {
    
    
    return EXIT_SUCCESS;
}


int main (void) {
    size_t outputMessageLen, outputHashLen;
    // BASIC TEST
    {
        
        std::unique_ptr<uint8_t[]> outputMessage, outputHash;
        assert(EXIT_SUCCESS == findHash(nullptr, 0, outputMessage, outputMessageLen, outputHash, outputHashLen));
        assert(outputHashLen == 32);
        //Check if the outputHash is correct for the outputMessage.
        //For instance, in CMD: "echo abcdef | xxd -r -ps | openssl sha256", where "abcdef" is a hexadecimal message
       
    }

    {
       
        std::unique_ptr<uint8_t[]> outputMessage, outputHash;
        uint8_t prefix[] = {0x12};
        assert(EXIT_SUCCESS == findHash(prefix, 8, outputMessage, outputMessageLen, outputHash, outputHashLen));
        assert(EXIT_SUCCESS == checkHash(prefix, 8, outputHash));
       
    }

    {
         
        std::unique_ptr<uint8_t[]> outputMessage, outputHash;
        uint8_t prefix[] = {0x12, 0x30};
        assert(EXIT_SUCCESS == findHash(prefix, 12, outputMessage, outputMessageLen, outputHash, outputHashLen));
        assert(EXIT_SUCCESS == checkHash(prefix, 12, outputHash));
        
    }

    // INVALID INPUT TEST
    {

        std::unique_ptr<uint8_t[]> outputMessage, outputHash;
        uint8_t prefix[] = {0x12, 0x30};
        assert(EXIT_FAILURE == findHash(nullptr, 10, outputMessage, outputMessageLen, outputHash, outputHashLen));
        assert(EXIT_FAILURE == findHash(prefix, 1000, outputMessage, outputMessageLen, outputHash, outputHashLen));
        assert(EXIT_FAILURE == findHash(prefix, 10, outputMessage, outputMessageLen, outputHash, outputHashLen, nullptr));
      
    }

    // BASIC TEST FOR 3 POINTS
    {
        std::unique_ptr<uint8_t[]> outputMessage, outputHash;
        uint8_t prefix[] = {0x12, 0x34};
        assert(EXIT_SUCCESS == findHash(prefix, 15, outputMessage, outputMessageLen, outputHash, outputHashLen, "sha384"));
        assert(EXIT_SUCCESS == checkHash(prefix, 15, outputHash));
    }

    return EXIT_SUCCESS;
}
#endif /* __PROGTEST__ */