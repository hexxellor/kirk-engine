// Test harness for kirk engine

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../libkirk/kirk_engine.h"

int main(int argc, char  *argv[])
{
	int res;
	u8 rnd[0x14];
	u8 rndbig[0x80];
	u8 keypair[0x3C];
	u8 newpoint[0x28];
	u8 mult_test[0x3c];
	u8 test17_fullsig[0x64];
	KIRK_CMD16_BUFFER ecdsa_sign;
	ECDSA_SIG signature;
	KIRK_CMD17_BUFFER ecdsa_test;
	// My private RIF
	
	// From NPEH90049 Demo NPUMDIMG Header SHA1 of 0xD8 bytes
	u8 test17_hash[0x14]= {
		0x2C, 0x39, 0xC1, 0x46, 0x22, 0xD5, 0x55, 0x02,
		0x3A, 0x03, 0xB1, 0x2D, 0x17, 0x00, 0x00, 0x36,
		0x8C, 0x28, 0xBD, 0x50
	};

	// From NPEH90049 Demo NPUMDIMG Header at offset 0xD8
	u8 test17_sig[0x28] = {
		0x4B, 0xBC, 0xBC, 0xB5, 0x01, 0x70, 0xCD, 0x23,
		0x20, 0x6F, 0x51, 0x9A, 0xBE, 0xD7, 0xD8, 0xCC,
		0x04, 0x56, 0x4C, 0x9E, 0x17, 0xE0, 0x1E, 0x2E,
		0x63, 0x12, 0x38, 0x60, 0x58, 0x0B, 0x21, 0x84,
		0x9F, 0x52, 0x13, 0xF1, 0x31, 0x2C, 0x6A, 0xBC
	};

	// Public NPUMDIMG Key from np9660.prx
	u8 rif_public[0x28] = {
		0x01, 0x21, 0xEA, 0x6E, 0xCD, 0xB2, 0x3A, 0x3E,
		0x23, 0x75, 0x67, 0x1C, 0x53, 0x62, 0xE8, 0xE2,
		0x8B, 0x1E, 0x78, 0x3B, 0x1A, 0x27, 0x32, 0x15,
		0x8B, 0x8C, 0xED, 0x98, 0x46, 0x6C, 0x18, 0xA3,
		0xAC, 0x3B, 0x11, 0x06, 0xAF, 0xB4, 0xEC, 0x3B

	};


	printf("Starting Test Harness...\n");
	
	// In the real world, you should use a secure way of generated a nice chunk of random data.
	// There are good OS-specific ways available on each platform normally. Use those!
	//
	// The two values for the fuse id can be grabbed from your personal device
	// by reading BC100090 for the first value and BC100094 for the second value.
	// Process them as u32 so the endian order stays correct.
	kirk_init2((u8*)"This is my test seed",20,0x12345678, 0xabcd );
	//kirk_init();
	
	// Test Random Generator
	printf("\nGenerating 2 random numbers...\n");
	sceUtilsBufferCopyWithRange(rndbig,0x77,0,0,0xE);
	hex_dump("Big Random Number", rndbig, 0x77);
		
	sceUtilsBufferCopyWithRange(rnd,0x14,0,0,0xE);
	hex_dump("Random Number", rnd, 0x14);
	
	// Test Key Pair Generator
	printf("\nGenerating a new ECDSA keypair...\n");
	sceUtilsBufferCopyWithRange(keypair,0x3C,0,0,0xC);
	hex_dump("Private Key", keypair, 0x14);
	hex_dump("Public Key", keypair+0x14, 0x28);
	
	// Test Point Multiplication
	printf("\nMultiplying the Public Key by the Random Number...\n");
	memcpy(mult_test,rnd,0x14);
	memcpy(mult_test+0x14,keypair+0x14,0x28);
	sceUtilsBufferCopyWithRange(newpoint,0x28,mult_test,0x3C,0xD);
	hex_dump("New point", newpoint, 0x28);
	
	printf("Testing a known valid ECDSA signature...\n");
	memcpy(test17_fullsig, rif_public,0x28);
	memcpy(test17_fullsig+0x28, test17_hash,0x14);
	memcpy(test17_fullsig+0x3C, test17_sig,0x28);
	res=sceUtilsBufferCopyWithRange(0,0,test17_fullsig,0x64,0x11);
	printf("Signature check returned %d\n", res);
	if(res) {
		printf("Signature FAIL!\n");
	} else {
		printf("Signature VALID!\n");
	}
	printf("\nTesting ECDSA signing with ECDSA key pair...\n");
	encrypt_kirk16_private(ecdsa_sign.enc_private,keypair);
	hex_dump("Encrypted Private", ecdsa_sign.enc_private, 0x20);
	//Test with a message hash of all 00s
	memset(ecdsa_sign.message_hash,0,0x14);
	sceUtilsBufferCopyWithRange(signature.r,0x28,ecdsa_sign.enc_private,0x34,0x10);
	
	printf("\nChecking signature and Message hash...\n");
	hex_dump("Signature R", signature.r, 0x14);
	hex_dump("Signature S", signature.s, 0x14);
	hex_dump("Message hash", ecdsa_sign.message_hash,0x14);
	
	printf("\nUsing Public key...\n");
	hex_dump("Public.x", keypair+0x14,0x14);
	hex_dump("Public.y", keypair+0x28,0x14);
	// Build ecdsa verify message block
	memcpy(ecdsa_test.public_key.x,keypair+0x14,0x14);
	memcpy(ecdsa_test.public_key.y,keypair+0x28,0x14);
	memcpy(ecdsa_test.message_hash,ecdsa_sign.message_hash,0x14);
	memcpy(ecdsa_test.signature.r,signature.r,0x14);
	memcpy(ecdsa_test.signature.s,signature.s,0x14);
	
	res=sceUtilsBufferCopyWithRange(0,0,(u8*)ecdsa_test.public_key.x,0x64,0x11);
	printf("Signature check returned %d\n", res);
	if(res) {
		printf("Signature FAIL!\n");
	} else {
		printf("Signature VALID!\n");
	}	
	return 0;
}
