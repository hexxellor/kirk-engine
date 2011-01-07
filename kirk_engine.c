/* 
	KIRK ENGINE CODE
	Thx for kgsws, Mathieulh, SilverSpring, Davee
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

u8 fuseID[16]; //Emulate FUSEID	

u8 kirk1_key[] =   {0x98, 0xC9, 0x40, 0x97, 0x5C, 0x1D, 0x10, 0xE8, 0x7F, 0xE6, 0x0E, 0xA3, 0xFD, 0x03, 0xA8, 0xBA};

u8 kirk7_key03[] = {0x98, 0x02, 0xC4, 0xE6, 0xEC, 0x9E, 0x9E, 0x2F, 0xFC, 0x63, 0x4C, 0xE4, 0x2F, 0xBB, 0x46, 0x68};
u8 kirk7_key04[] = {0x99, 0x24, 0x4C, 0xD2, 0x58, 0xF5, 0x1B, 0xCB, 0xB0, 0x61, 0x9C, 0xA7, 0x38, 0x30, 0x07, 0x5F};
u8 kirk7_key05[] = {0x02, 0x25, 0xD7, 0xBA, 0x63, 0xEC, 0xB9, 0x4A, 0x9D, 0x23, 0x76, 0x01, 0xB3, 0xF6, 0xAC, 0x17};
u8 kirk7_key0C[] = {0x84, 0x85, 0xC8, 0x48, 0x75, 0x08, 0x43, 0xBC, 0x9B, 0x9A, 0xEC, 0xA7, 0x9C, 0x7F, 0x60, 0x18};
u8 kirk7_key0D[] = {0xB5, 0xB1, 0x6E, 0xDE, 0x23, 0xA9, 0x7B, 0x0E, 0xA1, 0x7C, 0xDB, 0xA2, 0xDC, 0xDE, 0xC4, 0x6E};
u8 kirk7_key0E[] = {0xC8, 0x71, 0xFD, 0xB3, 0xBC, 0xC5, 0xD2, 0xF2, 0xE2, 0xD7, 0x72, 0x9D, 0xDF, 0x82, 0x68, 0x82};
u8 kirk7_key0F[] = {0x0A, 0xBB, 0x33, 0x6C, 0x96, 0xD4, 0xCD, 0xD8, 0xCB, 0x5F, 0x4B, 0xE0, 0xBA, 0xDB, 0x9E, 0x03};
u8 kirk7_key10[] = {0x32, 0x29, 0x5B, 0xD5, 0xEA, 0xF7, 0xA3, 0x42, 0x16, 0xC8, 0x8E, 0x48, 0xFF, 0x50, 0xD3, 0x71};
u8 kirk7_key11[] = {0x46, 0xF2, 0x5E, 0x8E, 0x4D, 0x2A, 0xA5, 0x40, 0x73, 0x0B, 0xC4, 0x6E, 0x47, 0xEE, 0x6F, 0x0A};
u8 kirk7_key12[] = {0x5D, 0xC7, 0x11, 0x39, 0xD0, 0x19, 0x38, 0xBC, 0x02, 0x7F, 0xDD, 0xDC, 0xB0, 0x83, 0x7D, 0x9D};
u8 kirk7_key38[] = {0x12, 0x46, 0x8D, 0x7E, 0x1C, 0x42, 0x20, 0x9B, 0xBA, 0x54, 0x26, 0x83, 0x5E, 0xB0, 0x33, 0x03};
u8 kirk7_key39[] = {0xC4, 0x3B, 0xB6, 0xD6, 0x53, 0xEE, 0x67, 0x49, 0x3E, 0xA9, 0x5F, 0xBC, 0x0C, 0xED, 0x6F, 0x8A};
u8 kirk7_key3A[] = {0x2C, 0xC3, 0xCF, 0x8C, 0x28, 0x78, 0xA5, 0xA6, 0x63, 0xE2, 0xAF, 0x2D, 0x71, 0x5E, 0x86, 0xBA};
u8 kirk7_key4B[] = {0x0C, 0xFD, 0x67, 0x9A, 0xF9, 0xB4, 0x72, 0x4F, 0xD7, 0x8D, 0xD6, 0xE9, 0x96, 0x42, 0x28, 0x8B}; //1.xx game eboot.bin
u8 kirk7_key53[] = {0xAF, 0xFE, 0x8E, 0xB1, 0x3D, 0xD1, 0x7E, 0xD8, 0x0A, 0x61, 0x24, 0x1C, 0x95, 0x92, 0x56, 0xB6};
u8 kirk7_key57[] = {0x1C, 0x9B, 0xC4, 0x90, 0xE3, 0x06, 0x64, 0x81, 0xFA, 0x59, 0xFD, 0xB6, 0x00, 0xBB, 0x28, 0x70};
u8 kirk7_key5D[] = {0x11, 0x5A, 0x5D, 0x20, 0xD5, 0x3A, 0x8D, 0xD3, 0x9C, 0xC5, 0xAF, 0x41, 0x0F, 0x0F, 0x18, 0x6F};
u8 kirk7_key63[] = {0x9C, 0x9B, 0x13, 0x72, 0xF8, 0xC6, 0x40, 0xCF, 0x1C, 0x62, 0xF5, 0xD5, 0x92, 0xDD, 0xB5, 0x82};
u8 kirk7_key64[] = {0x03, 0xB3, 0x02, 0xE8, 0x5F, 0xF3, 0x81, 0xB1, 0x3B, 0x8D, 0xAA, 0x2A, 0x90, 0xFF, 0x5E, 0x61};

u8* kirk_4_7_get_key(int key_type)
{
    switch(key_type)
	{
		case(0x03): return kirk7_key03; break;
		case(0x04): return kirk7_key04; break;
		case(0x05): return kirk7_key05; break;
		case(0x0C): return kirk7_key0C; break;
		case(0x0D): return kirk7_key0D; break;
		case(0x0E): return kirk7_key0E; break;
		case(0x0F): return kirk7_key0F; break;
		case(0x10): return kirk7_key10; break;
		case(0x11): return kirk7_key11; break;
		case(0x12): return kirk7_key12; break;
		case(0x38): return kirk7_key38; break;
		case(0x39): return kirk7_key39; break;
		case(0x3A): return kirk7_key3A; break;
		case(0x4B): return kirk7_key4B; break;
		case(0x53): return kirk7_key53; break;
		case(0x57): return kirk7_key57; break;
		case(0x5D): return kirk7_key5D; break;
		case(0x63): return kirk7_key63; break;
		case(0x64): return kirk7_key64; break;
		default: return (u8*)KIRK_INVALID_SIZE; break; //need to get the real error code for that, placeholder now :)
	}
}

int kirk_CMD1_decrypt(void* outbuff, void* inbuff, int size, KIRK_CMD1_HEADER* header)
{
	u8 decrypted_AES_key[16];
	
	AES_KEY aesKey;
	AES_set_decrypt_key(kirk1_key, 128, &aesKey);
	
	u8 ivec[16];
	memset(ivec, 0, sizeof(ivec));
	
	AES_cbc_encrypt(header->encrypted_AES_key, decrypted_AES_key, 16, &aesKey, ivec, AES_DECRYPT);
	
	AES_set_decrypt_key(decrypted_AES_key, 128, &aesKey);
	
	AES_cbc_encrypt(inbuff, outbuff, header->data_size, &aesKey, ivec, AES_DECRYPT);
	
	return KIRK_OPERATION_SUCCESS;
}

int kirk_AES_128_CBC_encrypt(void* outbuff, void* inbuff, int size, u8* key, u8* IV)
{
	if(key == (u8*)KIRK_INVALID_SIZE) return KIRK_INVALID_SIZE;
	
	if(size == 0) return KIRK_DATA_SIZE_ZERO;
	
	u8 ivec[16];
	memset(ivec, 0, sizeof(ivec));
	if(IV != NULL)
	{
	      memcpy(ivec, IV, sizeof(ivec));
	}
	
	//Set the key
	AES_KEY aesKey;
	AES_set_encrypt_key(key, 128, &aesKey);
	
 	AES_cbc_encrypt(inbuff, outbuff, size, &aesKey, ivec, AES_ENCRYPT);
	
	return KIRK_OPERATION_SUCCESS;
}

int kirk_AES_128_CBC_decrypt(void* outbuff, void* inbuff, int size, u8* key, u8* IV)
{
	if(key == (u8*)KIRK_INVALID_SIZE) return KIRK_INVALID_SIZE;
	
	if(size == 0) return KIRK_DATA_SIZE_ZERO;
	
	u8 ivec[16];
	memset(ivec, 0, sizeof(ivec));
	if(IV != NULL)
	{
	      memcpy(ivec, IV, sizeof(ivec));
	}
	
	//Set the key
	AES_KEY aesKey;
	AES_set_decrypt_key(key, 128, &aesKey);
	
	AES_cbc_encrypt(inbuff, outbuff, size, &aesKey, ivec, AES_DECRYPT);
	
	return KIRK_OPERATION_SUCCESS;
}

int sceUtilsSetFuseID(void*fuse)
{
	memcpy(fuseID, fuse, 16);
	return 0;
}

int sceUtilsBufferCopyWithRange(void* outbuff, int outsize, void* inbuff, int insize, int cmd)
{
	if(cmd ==KIRK_CMD_DECRYPT_PRIVATE)
	{
		return kirk_CMD1_decrypt(outbuff, inbuff+sizeof(KIRK_CMD1_HEADER), insize, (KIRK_CMD1_HEADER*)inbuff);
	}
	else
	if(cmd == KIRK_CMD_ENCRYPT_IV_0 || cmd == KIRK_CMD_ENCRYPT_IV_FUSE || cmd == KIRK_CMD_ENCRYPT_IV_USER)
	{
		u8* iv_crypt;
		int additional_data = 0;  //because the user IV key is after the header
		switch(cmd)
		{
			case(KIRK_CMD_ENCRYPT_IV_0): iv_crypt = NULL; break;
			case(KIRK_CMD_ENCRYPT_IV_FUSE): iv_crypt = fuseID; break;
			case(KIRK_CMD_ENCRYPT_IV_USER): additional_data = 16; iv_crypt = inbuff+sizeof(KIRK_AES128CBC_HEADER); break;
		}
		KIRK_AES128CBC_HEADER *header = (KIRK_AES128CBC_HEADER*)inbuff;
		return kirk_AES_128_CBC_encrypt(outbuff, inbuff+sizeof(KIRK_AES128CBC_HEADER)+additional_data, header->size, kirk_4_7_get_key(header->keyseed), iv_crypt);
	}
	else
	if(cmd == KIRK_CMD_DECRYPT_IV_0 || cmd == KIRK_CMD_DECRYPT_IV_FUSE || cmd == KIRK_CMD_DECRYPT_IV_USER)
	{
		u8* iv_crypt;
		int additional_data = 0; //because the user IV key is after the header
		switch(cmd)
		{
			case(KIRK_CMD_DECRYPT_IV_0): iv_crypt = NULL; break;
			case(KIRK_CMD_DECRYPT_IV_FUSE): iv_crypt = fuseID; break;
			case(KIRK_CMD_DECRYPT_IV_USER): additional_data = 16; iv_crypt = inbuff+sizeof(KIRK_AES128CBC_HEADER); break;
		}
		KIRK_AES128CBC_HEADER *header = (KIRK_AES128CBC_HEADER*)inbuff;
		return kirk_AES_128_CBC_decrypt(outbuff, inbuff+sizeof(KIRK_AES128CBC_HEADER)+additional_data, header->size, kirk_4_7_get_key(header->keyseed), iv_crypt);
	}
	return -1;
}
