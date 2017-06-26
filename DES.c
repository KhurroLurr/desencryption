// Nicholas Espinosa
// CIS 3362 - 0001
// 10.22.2015
// DES Encryption 

// The following code is adapted from the DES Encrypter written by Arup Guha
// The orginal source code can be found at
// http://www.cs.ucf.edu/~dmarino/ucf/cis3362/progs/

// Please place the file destables.txt in the same directory as this file when running
// The file can be located in the same location as the original source

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Struct containing the information for DES encryption
typedef struct DESInformation
{
	int key[64];
	int roundkeys[16][48];
	int block[64];
	int stables[8][4][16];
	int IP[64];
	int IPInv[64];
	int E[48];
	int PC2[48];
	int P[32];
	int PC1[56];
	int keyshifts[16];	
} DES;

// Obtaining the constants for DES
void getInfo(DES *des)
{
	int i, j;
	FILE *ifp  = fopen("destables.txt", "r"); // Opening file

	// Obtaining the Initial Permutation Table
	for (i = 0; i < 64; i++)
		fscanf(ifp, "%d", &des->IP[i]);

	// Obtaining the Initial Permutation Inverse Table
	for (i = 0; i < 64; i++)
		fscanf(ifp, "%d", &des->IPInv[i]);

	// Obtaining the Expansion Table
	for (i = 0; i < 48; i++)
		fscanf(ifp, "%d", &des->E[i]);

	// Obtaining permutation matrix P used in each round.
	for (i = 0; i < 32; i++)
		fscanf(ifp, "%d", &des->P[i]);

	// Obtaining the S-Boxes
	for (i=0; i < 8; i++) 
		for (j = 0; j < 64; j++)
			fscanf(ifp, "%d", &des->stables[i][j/16][j%16]);
		
	// Obtaining PC1
	for (i = 0; i < 56; i++)
		fscanf(ifp, "%d", &des->PC1[i]);
		
	// Obtaining PC2	
	for (i = 0; i < 48; i++)
		fscanf(ifp, "%d", &des->PC2[i]);
			
	// Obtaining KeyShifts
	for (i = 0; i < 16; i++)
		fscanf(ifp, "%d", &des->keyshifts[i]);
	
	// Closing file
	fclose(ifp);
}

// Obtaining the input from the file
void getInput(DES *des, int input)
{
	int i, j, value;
	char word[17];
	
	// Plcaing input into char array
	scanf("%s", word);	

	// Finds int value of each hexadecimal letter
	for (i = 0; i < 16; i++) 
	{
		// Converting to lower case
		word[i] = tolower(word[i]);

		// Determining the integer value of the character
		value = (int)word[i];
			
		// Converting to the correct integer value
		if ('0' <= value && value <= '9')
			value -= '0';
		else
			value = value - 'a' + 10;
			
		// Placing into binary array
		for (j = 3; j >= 0; j--) 
		{
			// Determining if the value entered is for key or block
			if(input == 0)
				des->key[4 * i + j] = value % 2;
			else if(input == 1)
				des->block[4 * i + j] = value % 2;

			value /= 2;
		}
	}
}	

// Performing DES encryption
void encrypt(DES des)
{
	int i, j, k, row, col, temp, power = 1, leftVal = 0, rightVal = 0;
	int block[64], left[32], right[32], xor[48], sboxout[48], fout[32], final[64];

	// Performing the initial permutation
	for(i = 0; i < 64; i++)
		block[i] = des.block[des.IP[i]-1];

	// Obtaining the left and right side
	for(i = 0; i < 32; i++)
	{
		left[i] = block[i];
		right[i] = block[32 + i];
	}

	// Core of the encryption process
	for(i = 0; i < 16; i++)
	{
		// Performing Expansion and first XOR
		for(j = 0; j < 48; j++)
			xor[j] = right[des.E[j] - 1] ^ des.roundkeys[i][j];
			
		// Determining the S-Box output
		for (j = 0; j < 8; j++) 
		{
			// Determining row and column
			row = 2 * xor[6 * j] + xor[6 * j + 5];
			col = (8 * xor[6 * j + 1] + 4 * xor[6 * j + 2] + 2 * xor[6 * j + 3] + xor[6 * j + 4]) % 16;
	
			// Setting temp equal to that value
			temp = des.stables[j][row][col];
			
			// Converting that value to binary
			for (k = 3; k >= 0; k--) 
			{
				sboxout[4 * j + k] = temp % 2;
				temp /= 2;
			}
		}
		
		// Fout permutation and XOR with left side
		for(j = 0; j < 32; j++)
			fout[j] = sboxout[des.P[j] - 1] ^ left[j];

		// Establishing left and right side for next round
		for(j = 0; j < 32; j++)
		{
			left[j] = right[j];
			right[j] = fout[j];
		}
	}
	
	//Swapping left and right half
	for(i = 0; i < 32; i++)
	{
		block[i] = right[i];
		block[i + 32] = left[i];
	}
	
	//Permute with IPInv
	for(i = 0; i < 64; i++)
		final[i] = block[des.IPInv[i] - 1];
	
	// Placing the values into two integers
	for(i = 31; i >= 0; i--)
	{
		leftVal = leftVal + final[i] * power;
		rightVal = rightVal + final[i + 32] * power;
		power = power * 2;
	}
	
	// Printing out the final value
	printf("%08x%08x\n", leftVal, rightVal);	
}

// Performing a left shift
void leftShift(int *key, int start, int end, int numbits) 
{
	int i, size = end - start + 1, *temp;

	// Allocating necessary data
	temp = malloc(sizeof(int) * size);
		
	// PLacing bits into the new order
	for (i = 0; i < size; i++)
		temp[i] = key[start + (numbits + i) % size];	
		
	// Placing values back into the original array
	for (i = 0; i < size; i++)
		key[start + i] = temp[i];

	// Freeing unnecessary data
	free(temp);
}

// Setting up the keys for the operations
void setKeys(DES *des)
{
	int i, j, *key = malloc(sizeof(int) * 56);

	//Obtaining the key
	for(i = 0; i < 56; i++)
		key[i] = des->key[des->PC1[i] - 1];	
		
	// Determines the roundkeys for the encryption
	for (i = 0; i < 16; i++) 
	{	
		// Performs the left shift operation based upon keyshifts
		leftShift(key, 0, 27, des->keyshifts[i]);
		leftShift(key, 28, 55, des->keyshifts[i]);
			
		// Now, just copy in the (i+1)th round key.
		for (j = 0; j < 48; j++)
			des->roundkeys[i][j] = key[des->PC2[j] - 1];	
	}
	
	free(key);
}

// Main function
int main()
{
	DES des;
	int i, numSeq;

	// Obtaining the constants for DES
	getInfo(&des);
	
	// Obtaining Key
	getInput(&des, 0);

	// Establishing the keys that will be used
	setKeys(&des);

	// Obtaining the number of DES operations to perform
	scanf("%d", &numSeq);

	// For each instance of des
	for(i = 0; i < numSeq; i++)
	{
		// Obtaining the word that will be enctrypted
		getInput(&des, 1);

		// Encrypting the word
		encrypt(des);
	}	

	return 0;
}
