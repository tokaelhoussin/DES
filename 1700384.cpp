#include <iostream>
#include <intrin.h>
using namespace std;

typedef unsigned long long u64;
typedef unsigned char byte1;
u64 RoundKey;
u64 rkb[16];

u64 reverse_rkb[16];
void reverse(u64* arr) {
	int j = 15;
	for (int i = 0; i<16; i++)
	{
		reverse_rkb[i] = rkb[15 - i];
	}
}
u64 permute(int N,u64 k, int* arr, int n)
{
	u64 per = 0;
	for (int i = 0; i < n; i++) {
		per |= (k >> (N - arr[i]) & 1) << n-(i+1);
	}
	return per;
}	
u64 read_u64_hex(const char *data)
{
	u64 ret = 0;
	for (;; ++data)//read left- to- right
	{
		byte1 dec = (*data)- '0';
		if (dec<10)
			ret = ret << 4 | dec;
		else {
			byte1 upper1 = (*data & 0xDF)- 'A';
			if (upper1>5)
				break;
			ret = ret << 4 | upper1 + 10;
		}
	}
	return ret;
}
void key_transformation(u64 key) {
	// permutation_choice1
	int keyp[56] = { 57, 49, 41, 33, 25, 17, 9,
		1, 58, 50, 42, 34, 26, 18,
		10, 2, 59, 51, 43, 35, 27,
		19, 11, 3, 60, 52, 44, 36,
		63, 55, 47, 39, 31, 23, 15,
		7, 62, 54, 46, 38, 30, 22,
		14, 6, 61, 53, 45, 37, 29,
		21, 13, 5, 28, 20, 12, 4 };

	// getting 56 bit key from 64 bit using the pc1
	key = permute(64,key, keyp, 56); // key without pc1

	// Number of bit shifts
	int shift_table[16] = { 1, 1, 2, 2,
		2, 2, 2, 2,
		1, 2, 2, 2,
		2, 2, 2, 1 };

	// permutation_choice2
	int key_comp[48] = { 14, 17, 11, 24, 1, 5,
		3, 28, 15, 6, 21, 10,
		23, 19, 12, 4, 26, 8,
		16, 7, 27, 20, 13, 2,
		41, 52, 31, 37, 47, 55,
		30, 40, 51, 45, 33, 48,
		44, 49, 39, 56, 34, 53,
		46, 42, 50, 36, 29, 32 };

	// Splitting
	u64 left = (key >> 28)& 0x0000000FFFFFFF;
	u64 right = key & 0x0000000FFFFFFF;

	for (int i = 0; i < 16; i++) {
		// Shifting
		left = (left << shift_table[i]) | (left >> (28 - shift_table[i]));
		right = (right << shift_table[i]) | (right >> (28 - shift_table[i]));

		// Combining
		u64 combine = ( right& 0x0000000FFFFFFF)|((left<<28)& 0xFFFFFFF0000000);

		// Key Compression
		RoundKey = permute(56,combine, key_comp, 48);
		rkb[i] = RoundKey;
	}
}


u64 encrypt(u64 pt,u64* key)
{
	// Hexadecimal to binary
	//pt = hex2bin(pt);

	// Initial Permutation Table
	int initial_perm[64] = { 58, 50, 42, 34, 26, 18, 10, 2,
		60, 52, 44, 36, 28, 20, 12, 4,
		62, 54, 46, 38, 30, 22, 14, 6,
		64, 56, 48, 40, 32, 24, 16, 8,
		57, 49, 41, 33, 25, 17, 9, 1,
		59, 51, 43, 35, 27, 19, 11, 3,
		61, 53, 45, 37, 29, 21, 13, 5,
		63, 55, 47, 39, 31, 23, 15, 7 };
	// Initial Permutation
	pt = permute(64,pt, initial_perm, 64);

	// Splitting
	u64 left = (pt >> 32) & 0x00000000FFFFFFFF;
	u64 right = pt   & 0x00000000FFFFFFFF;
	

	// Expansion box Table
	int exp_d[48] = { 32, 1, 2, 3, 4, 5, 4, 5,
		6, 7, 8, 9, 8, 9, 10, 11,
		12, 13, 12, 13, 14, 15, 16, 17,
		16, 17, 18, 19, 20, 21, 20, 21,
		22, 23, 24, 25, 24, 25, 26, 27,
		28, 29, 28, 29, 30, 31, 32, 1 };

	// S-box Table
	int s[512] = { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
		0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
		4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
		15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 ,
		15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
		3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
		0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
		13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 ,

		 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
		13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
		13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
		1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 ,
		 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
		13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
		10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
		3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 ,
		 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
		14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
		4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
		11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 ,
		 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
		10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
		9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
		4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 ,
		 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
		13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
		1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
		6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 ,
		 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
		1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
		7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
		2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11  };

	//Permutation Table
	int per[32] = { 16, 7, 20, 21,
		29, 12, 28, 17,
		1, 15, 23, 26,
		5, 18, 31, 10,
		2, 8, 24, 14,
		32, 27, 3, 9,
		19, 13, 30, 6,
		22, 11, 4, 25 };

	for (int i = 0; i < 16; i++) {
		// Expansion D-box
		u64 right_expanded = permute(32,right, exp_d, 48);

		// XOR RoundKey[i] and right_expanded
		u64 x = key[i]^right_expanded;

		// S-boxes

		u64 result=0;
		int box[64];
		for (int i = 0; i < 8; i++) {
			for (int j= 0; j < 64; j++) {
				 box[j]= s[j+(i * 64)];
			}
			u64	idx = x >> (7 - i) * 6 & 0x3F; //get the index
			idx = idx >> 1 & 15 | (idx & 1) << 4 | idx & 0x20; //reorder bits
			result |= box[idx] << (7 - i) * 4;

		}
		// Straight D-box
		result = permute(32,result, per, 32);

		// XOR left and op
		x = result^left;

		left = x;

		// Swapper
		if (i != 15) {
			swap(left, right);
		}
	}

	// Combination
	u64 combine = (right & 0x00000000FFFFFFFF) | ((left << 32) & 0xFFFFFFFF00000000);;

	// Final Permutation Table
	int final_perm[64] = { 40, 8, 48, 16, 56, 24, 64, 32,
		39, 7, 47, 15, 55, 23, 63, 31,
		38, 6, 46, 14, 54, 22, 62, 30,
		37, 5, 45, 13, 53, 21, 61, 29,
		36, 4, 44, 12, 52, 20, 60, 28,
		35, 3, 43, 11, 51, 19, 59, 27,
		34, 2, 42, 10, 50, 18, 58, 26,
		33, 1, 41, 9, 49, 17, 57, 25 };

	// Final Permutation
	u64 cipher = permute(64,combine, final_perm, 64);
	return cipher;
}

int main(int argc, char** argv)
{
	if (argc == 4) {
		if (strcmp("encrypt", argv[1]) == 0) {
			u64 key = read_u64_hex(argv[3]);
			key_transformation(key); 
			u64 data = read_u64_hex(argv[2]); 
			u64 t1 = __rdtsc();
			u64 cipher = encrypt(data,rkb);
			u64 t2 = __rdtsc();
			printf( "Cipher: %016llX\n" , cipher );
			printf("Cycles: %lld\n", t2 - t1);
		}
		else if (strcmp("decrypt", argv[1]) == 0) {
      		u64 key = read_u64_hex(argv[3]);
		    key_transformation(key);
			reverse(rkb);
			//reverse(rkb.begin(), rkb.end());
			//reverse(rk.begin(), rk.end());
			u64 cipher = read_u64_hex(argv[2]);
			u64 t1 = __rdtsc();
			u64 text = encrypt(cipher,reverse_rkb);
			u64 t2 = __rdtsc();
			printf( "Plain: %016llX\n" , text );
			printf("Cycles: %lld\n", t2 - t1);
		}
	}
	return 0;
}