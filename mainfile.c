#include <stdio.h>
#include <string.h>
#include "grain.h"

/*  GENERATE TEST VECTORS  */

void printData(int *key, int *IV, int *ks, int *pt, int *et, int *dt) {
	int i;
	printf("key:        ");
	for (i=0;i<10;++i) printf("%02x",(int)key[i]);
	printf("\nIV :        ");
	for (i=0;i<8;++i) printf("%02x",(int)IV[i]);
	printf("\nkeystream:  ");
	for (i=0;i<10;++i) printf("%02x",(int)ks[i]);
	printf("\nplaintext:  ");
	for (i=0;i<10;i++) printf("%02x",(int)pt[i]);
	printf("\nencrypted text:  ");
	for (i=0;i<10;i++) printf("%02x",(int)et[i]);
	printf("\ndecrypted text:  ");
	for (i=0;i<10;i++) printf("%02x",(int)dt[i]);
}

int main(int argc, char **argv) {
	
	int plaintext[10]={0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01};
	int encrypted_text[10];
	int decrypted_text[10];

	grain mygrain;
	int key1[10] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
		IV1[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
	    ks[10];

	int key2[10] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x12,0x34},
		IV2[8] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};

	printf("\nTestCase: 1\n");
	keysetup(&mygrain,key1,80,64);
	ivsetup(&mygrain,IV1);
	keystream_bytes(&mygrain,ks,10);
	grain mygrain2 = mygrain;
	encrypt_bytes(&mygrain,plaintext,encrypted_text,10);
	decrypt_bytes(&mygrain2,encrypted_text,decrypted_text,10);
	printData(key1,IV1,ks, plaintext, encrypted_text, decrypted_text);


	printf("\n\nTestCase: 2\n");
	keysetup(&mygrain,key2,80,64);
	ivsetup(&mygrain,IV2);
	keystream_bytes(&mygrain,ks,10);
	mygrain2 = mygrain;
	encrypt_bytes(&mygrain,plaintext,encrypted_text,10);
	decrypt_bytes(&mygrain2,encrypted_text,decrypted_text,10);
	printData(key2,IV2,ks, plaintext, encrypted_text, decrypted_text);

	printf("\n");
	return 0;
}