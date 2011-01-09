#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kirk_engine.h"

//IPL-DECRYPTER SAMPLE

typedef struct
{
    void *loadaddr;
    u32 blocksize;
    void (* entry)(void);
    u32 checksum;
    u8 data[0xF50];
} IplBlock;

u8 buf[0x1000];
u8 decrypted[0x1000];

void printHEX(int hex)
{
	if(hex < 0x10) printf("0%X", hex);
	else printf("%X", hex);
}

void PrintKIRK1Header(u8* buf)
{
    KIRK_CMD1_HEADER* header = (KIRK_CMD1_HEADER*)buf;
    printf("AES encrypted key:\n");
    int i;
    for(i = 0; i < 16; i++)
    {
		printHEX(header->AES_key[i]);
    }
    printf("\nCMAC encrypted key:\n");
    for(i = 0; i < 16; i++)
    {
		printHEX(header->CMAC_key[i]);
    }
    printf("\nCMAC header hash:\n");
    for(i = 0; i < 16; i++)
    {
		printHEX(header->CMAC_header_hash[i]);
    }
    printf("\nCMAC data hash:\n");
    for(i = 0; i < 16; i++)
    {
		printHEX(header->CMAC_data_hash[i]);
    }
    printf("\nmode: %d, data_size 0x%X, data_offset 0x%X\n", header->mode, header->data_size, header->data_offset);
}
int main()
{
	//init the kirk "hardware"
    kirk_init(); 
	
	//Open the file to decrypt, get it's size
    FILE *in = fopen("nandipl_01g.bin", "rb"); //works also on nandipl from 02g, should on others too
    fseek(in, 0, SEEK_END);
    int size = ftell(in);
    rewind(in);
	
	//Open the output file
	FILE *o = fopen("decrypted.bin", "wb");
	
	//Before the code in IPL block exist 16 bytes of information for pre-ipl, described as IplBlock struct(without the "data" of course). 
	//For some reason I can't decrypt it, and without information from it I can't merge the decrypted ipl correctly.
	//What I do now is just decrypt & save blocks in the same order as they're in encrypted IPL.
	int i;
    for(i = 0; i < size; i+= 0x1000)
    {
		fseek(in, i, SEEK_SET);
        fread(buf, 0x1000, 1, in);
		PrintKIRK1Header(buf);
		int ret = kirk_CMD1(decrypted, buf, 0x1000);
		if(ret == KIRK_NOT_ENABLED){ printf("KIRK not enabled!\n"); break;}
		else if(ret == KIRK_INVALID_MODE){ printf("Mode in header not CMD1\n"); break;}
		else if(ret == KIRK_HEADER_HASH_INVALID){ printf("header hash check failed\n"); break;}
		else if(ret == KIRK_DATA_HASH_INVALID){ printf("data hash check failed\n"); break;}
		else if(ret == KIRK_DATA_SIZE_ZERO){ printf("data size = 0\n"); break;}
		else printf("Decrypt Success!\n\n");
		
		fseek(o, i, SEEK_SET);
        fwrite(decrypted, 0x1000, 1, o);
    }
	fclose(o);
    fclose(in);
    
    system("PAUSE");
	
	return 0;
}
