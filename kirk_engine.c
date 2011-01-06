/* 
	KIRK ENGINE CODE
	Thx for kgsws, Mathieulh, SilverSpring
*/


#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include "kirk_engine.h"

/*
KIRK cmd 7 key list
type 0x03: 9802C4E6EC9E9E2FFC634CE42FBB4668
type 0x04: 99244CD258F51BCBB0619CA73830075F
type 0x05: 0225D7BA63ECB94A9D237601B3F6AC17
type 0x0C: 8485C848750843BC9B9AECA79C7F6018
type 0x0D: B5B16EDE23A97B0EA17CDBA2DCDEC46E
type 0x0E: C871FDB3BCC5D2F2E2D7729DDF826882
type 0x0F: 0ABB336C96D4CDD8CB5F4BE0BADB9E03
type 0x10: 32295BD5EAF7A34216C88E48FF50D371
type 0x11: 46F25E8E4D2AA540730BC46E47EE6F0A
type 0x12: 5DC71139D01938BC027FDDDCB0837D9D
type 0x38: 12468D7E1C42209BBA5426835EB03303
type 0x39: C43BB6D653EE67493EA95FBC0CED6F8A
type 0x3A: 2CC3CF8C2878A5A663E2AF2D715E86BA
type 0x4B: 0CFD679AF9B4724FD78DD6E99642288B
type 0x53: AFFE8EB13DD17ED80A61241C959256B6
type 0x57: 1C9BC490E3066481FA59FDB600BB2870
type 0x5D: 115A5D20D53A8DD39CC5AF410F0F186F
type 0x63: 9C9B1372F8C640CF1C62F5D592DDB582
type 0x64: 03B302E85FF381B13B8DAA2A90FF5E61
*/

u8 kirk7_key03[] = {0x98, 0x02, 0xC4, 0xE6, 0xEC, 0x9E, 0x9E, 0x2F, 0xFC, 0x63, 0x4C, 0xE4, 0x2F, 0xBB, 0x46, 0x68};
u8 kirk7_key4B[] = {0x0C, 0xFD, 0x67, 0x9A, 0xF9, 0xB4, 0x72, 0x4F, 0xD7, 0x8D, 0xD6, 0xE9, 0x96, 0x42, 0x28, 0x8B}; //1.xx game eboot.bin

u8* kirk7_get_key(int key_type)
{
    switch(key_type)
	{
		case(0x03): return kirk7_key03; break;
		case(0x4B): return kirk7_key4B; break;
		default: return (u8*)KIRK_INVALID_SIZE; break; //need to get the real error code for that, placeholder now :)
	}
}

int kirk7_encrypt(void* outbuff, void* inbuff, int size, int key_type)
{
	u8* key = kirk7_get_key(key_type);
	if(key == (u8*)KIRK_INVALID_SIZE) return KIRK_INVALID_SIZE;
	
	if(size == 0) return KIRK_DATA_SIZE_ZERO;
	
	
	u8 ivec[16];
	memset(ivec, 0, sizeof(ivec));  // all zero for CMD 7
	
	//Set the key
	AES_KEY aesKey;
	AES_set_encrypt_key(key, 128, &aesKey);
	
	AES_cbc_encrypt(inbuff, outbuff, size, &aesKey, ivec, AES_ENCRYPT);
	
	return KIRK_OPERATION_SUCCESS;
}

int kirk7_decrypt(void* outbuff, void* inbuff, int size, int key_type)
{
	u8* key = kirk7_get_key(key_type);
	if(key == (u8*)KIRK_INVALID_SIZE) return KIRK_INVALID_SIZE;
	
	if(size == 0) return KIRK_DATA_SIZE_ZERO;
	
	
	u8 ivec[16];
	memset(ivec, 0, sizeof(ivec));  // all zero for CMD 7
	
	//Set the key
	AES_KEY aesKey;
	AES_set_decrypt_key(key, 128, &aesKey);
	
	AES_cbc_encrypt(inbuff, outbuff, size, &aesKey, ivec, AES_DECRYPT);
	
	return KIRK_OPERATION_SUCCESS;
}
	
