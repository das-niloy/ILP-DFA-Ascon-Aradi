#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>   // add once globally

typedef uint64_t bit64;
typedef uint8_t bit;

int faulty_calls = 0;

bit64 constants[12] = {0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b};

bit64 printx( bit64 x){
  printf("%" PRIX64"\n", x);
}

bit64 print_state(bit64 state[5]){
   for(int i = 0; i < 5; i++){
      printf("%" PRIX64"\n", state[i]);
   } 
}

void print_d_table( bit d_table[64][5][2]){
  for(int j=0; j<64; j++){
    for(int i=0; i<5; i++){
      printf("%d%d\t", d_table[j][i][0],d_table[j][i][1]);
    }
    printf("\n");
  }
}

bit64 rotate(bit64 x, int l){
   bit64 temp;
   temp = (x >> l) ^ (x << (64 - l));
   return temp;
}

void add_constant(bit64 state[5], int i, int a){
      state[2] = state[2] ^ constants[12 - a + i];
}

void sbox(bit64 x[5]){
    bit64 t[5] = { 0 };
    x[0] ^= x[4]; x[4] ^= x[3]; x[2] ^= x[1];
    t[0] = x[0]; t[1] = x[1]; t[2] = x[2]; t[3] = x[3]; t[4] = x[4];
    t[0] =~ t[0]; t[1] =~ t[1]; t[2] =~ t[2]; t[3] =~ t[3]; t[4] =~ t[4];
    t[0] &= x[1]; t[1] &= x[2]; t[2] &= x[3]; t[3] &= x[4]; t[4] &= x[0];
    x[0] ^= t[1]; x[1] ^= t[2]; x[2] ^= t[3]; x[3] ^= t[4]; x[4] ^= t[0];
    x[1] ^= x[0]; x[0] ^= x[4]; x[3] ^= x[2]; x[2] =~ x[2];
}

void linear(bit64 state[5]){
   bit64 temp0, temp1;
   temp0 = rotate(state[0], 19);
   temp1 = rotate(state[0], 28);
   state[0] ^= temp0 ^ temp1;
   temp0 = rotate(state[1], 61);
   temp1 = rotate(state[1], 39);
   state[1] ^= temp0 ^ temp1;
   temp0 = rotate(state[2], 1);
   temp1 = rotate(state[2], 6);
   state[2] ^= temp0 ^ temp1;
   temp0 = rotate(state[3], 10);
   temp1 = rotate(state[3], 17);
   state[3] ^= temp0 ^ temp1;
   temp0 = rotate(state[4], 7);
   temp1 = rotate(state[4], 41);
   state[4] ^= temp0 ^ temp1;
}

void round_permutation(bit64 state[5], int a){
   for (int i = 0; i < a; i++){
      add_constant(state, i, a);
      sbox(state);
      linear(state);
   }
}

void initialization(bit64 state[5], bit64 key[2]){
   round_permutation(state, 12);
   state[3] ^= key[0];
   state[4] ^= key[1];
}

void associated_data(bit64 state[5], int length, bit64 associated_data_text[]){
   for (int i = 0; i < length; i++){
      state[0] = associated_data_text[i] ^ state[0];
      round_permutation(state, 6);
    }
   state[4] = state[4] ^ 0x0000000000000001;
}

void finalization(bit64 state[5], bit64 key[2]){
   state[1] ^= key[0];
   state[2] ^= key[1];
   round_permutation(state, 12);
   state[3] ^= key[0];
   state[4] ^= key[1];
}

void plaintext_phase(bit64 state[5], int length, bit64 plaintext[], bit64 ciphertext[]) {
   ciphertext[0] = plaintext[0] ^ state[0];
   state[0]= ciphertext[0];
   for (int i = 1; i < length; i++){
      round_permutation(state, 6);
      ciphertext[i] = plaintext[i] ^ state[0];
      state[0] = ciphertext[i];
    }
}

void encryption(bit64 associated_data_text[], bit64 nonce[], bit64 key[], bit64 plaintext[], bit64 ciphertext[], bit64 tag[]){
  bit64 state[5] = {0};
  bit64 IV = 0x80400c0600000000;
  state[0] = IV;
  state[1] = key[0];
  state[2] = key[1];
  state[3] = nonce[0];
  state[4] = nonce[1];
  initialization(state,key);
  associated_data(state, 3, associated_data_text);
  plaintext_phase(state, 2, plaintext, ciphertext);
  finalization(state, key);
  tag[0]=state[3];
  tag[1]=state[4];
}

void ciphertext_phase(bit64 state[5], int length, bit64 plaintext[], bit64 ciphertext[]){
   plaintext[0] = ciphertext[0] ^ state[0];
   state[0]= ciphertext[0];
   for (int i = 1; i < length; i++){
      round_permutation(state, 6);
      plaintext[i] = ciphertext[i] ^ state[0];
      state[0] = ciphertext[i];
    }
}

void decryption(bit64 associated_data_text[], bit64 nonce[], bit64 key[], bit64 plaintext[], bit64 ciphertext[], bit64 tag1[2], bit64 tag[], int* flag){
   bit64 state[5] = {0};
   bit64 IV = 0x80400c0600000000;
   state[0] = IV;
   state[1] = key[0];
   state[2] = key[1];
   state[3] = nonce[0];
   state[4] = nonce[1];
   initialization(state,key);
   associated_data(state, 3, associated_data_text);
   ciphertext_phase(state, 2, plaintext, ciphertext);
   finalization(state, key);
   tag1[0] = state[3];
   tag1[1] = state[4];
   
   if(tag[0] == tag1[0] && tag[1] == tag1[1])
      *flag=1;
   else
      *flag=0;
}

/*  Constructing Table Offline: Required Tools    */

/*	5 Bit S-box    */

void bit_sbox(bit x[5]) {
    bit t[5] = { 0 };
    x[0] ^= x[4]; 
    x[4] ^= x[3]; 
    x[2] ^= x[1];
    for (int i = 0; i < 5; i++) {
        t[i] = x[i];
    }
    for (int i = 0; i < 5; i++) {
        t[i] = ~t[i] & 1;
    }
    t[0] &= x[1]; 
    t[1] &= x[2]; 
    t[2] &= x[3]; 
    t[3] &= x[4]; 
    t[4] &= x[0];

    x[0] ^= t[1]; 
    x[1] ^= t[2]; 
    x[2] ^= t[3]; 
    x[3] ^= t[4]; 
    x[4] ^= t[0];

    x[1] ^= x[0]; 
    x[0] ^= x[4]; 
    x[3] ^= x[2]; 
    x[2] = ~x[2] & 1;
}

void print_bit5(bit x[5]) {
    for (int i = 0; i < 5; i++) {
        printf("%d, ", x[i]);
    }
    printf("\n");
}

void pre_computation(bit f_table[32][5][2]){
  bit x[32][5] = {{0,0,0,0,0},{0,0,0,0,1},{0,0,0,1,0},{0,0,0,1,1},{0,0,1,0,0},{0,0,1,0,1},{0,0,1,1,0},{0,0,1,1,1},{0,1,0,0,0},{0,1,0,0,1},{0,1,0,1,0},{0,1,0,1,1},{0,1,1,0,0},{0,1,1,0,1},{0,1,1,1,0},{0,1,1,1,1},{1,0,0,0,0},{1,0,0,0,1},{1,0,0,1,0},{1,0,0,1,1},{1,0,1,0,0},{1,0,1,0,1},{1,0,1,1,0},{1,0,1,1,1},{1,1,0,0,0},{1,1,0,0,1},{1,1,0,1,0},{1,1,0,1,1},{1,1,1,0,0},{1,1,1,0,1},{1,1,1,1,0},{1,1,1,1,1}};

  bit sx[32][5] = {{0,0,1,0,0},{0,1,0,1,1},{1,1,1,1,1},{1,0,1,0,0},{1,1,0,1,0},{1,0,1,0,1},{0,1,0,0,1},{0,0,0,1,0},{1,1,0,1,1},{0,0,1,0,1},{0,1,0,0,0},{1,0,0,1,0},{1,1,1,0,1},{0,0,0,1,1},{0,0,1,1,0},{1,1,1,0,0},{1,1,1,1,0},{1,0,0,1,1},{0,0,1,1,1},{0,1,1,1,0},{0,0,0,0,0},{0,1,1,0,1},{1,0,0,0,1},{1,1,0,0,0},{1,0,0,0,0},{0,1,1,0,0},{0,0,0,0,1},{1,1,0,0,1},{1,0,1,1,0},{0,1,0,1,0},{0,1,1,1,1},{1,0,1,1,1}};

  bit delta_x[5][5] = { {1, 0, 0, 0, 0}, {0, 1, 0, 0, 0}, {0, 0, 1, 0, 0}, {0, 0, 0, 1, 0}, {0, 0, 0, 0, 1} };  // Input Difference
  for(int i = 0; i < 32; i++){
    for(int j = 0; j < 5; j++){
      bit y[5] = {0};
      bit delta_s[5] ={0};
      for(int m = 0; m < 5; m++){
        y[m] = x[i][m] ^ delta_x[j][m];
      }
      bit_sbox(y);
      for(int m = 0; m < 5; m++){
        delta_s[m] = sx[i][m] ^ y[m];
      }
      f_table[i][j][0] = delta_s[3];
      f_table[i][j][1] = delta_s[4];
    }
  }
}

/* Construct Table Online:  Required Tools Faulty Oracle*/

void faulty_finalization(bit64 state[5], bit64 key[2], int i, int j){
   state[1] ^= key[0];
   state[2] ^= key[1];
   for (int i = 0; i < 11; i++){
      add_constant(state, i, 12);
      sbox(state);
      linear(state);
   }
   add_constant(state, 11, 12);
   state[i] = state[i] ^ ( 0x8000000000000000 >> j );                           //Injecting Bit-Flip Fault at (i, j)-th position
   sbox(state);
   linear(state);
   state[3] ^= key[0];
   state[4] ^= key[1];
}

void faulty_decryption(bit64 associated_data_text[], bit64 nonce[], bit64 key[], bit64 plaintext[], bit64 ciphertext[], bit64 tag1[2], bit64 faulty_tag[], int* flag, int i, int j){
   faulty_calls++;   // ADD THIS LINE
   bit64 state[5] = {0};
   bit64 IV = 0x80400c0600000000;
   state[0] = IV;
   state[1] = key[0];
   state[2] = key[1];
   state[3] = nonce[0];
   state[4] = nonce[1];
   initialization(state,key);
   associated_data(state, 3, associated_data_text);
   ciphertext_phase(state, 2, plaintext, ciphertext);
   
   faulty_finalization(state, key, i, j);
   tag1[0] = state[3];
   tag1[1] = state[4];
   
   if(faulty_tag[0] == tag1[0] && faulty_tag[1] == tag1[1])
      *flag=1;
   else
      *flag=0;
}

void bit_dif(bit64 associated_data_text[], bit64 nonce[2], bit64 key[2],
             bit64 plaintext[], bit64 ciphertext[], bit64 tag[2],
             int i, int j, bit b[2])
{
    bit64 L[4] = {0x0, 0x1, 0x2, 0x3};
    int used[4] = {0};   // track used indices
    int order[4];        // random permutation

    // ---- generate random permutation of {0,1,2,3} ----
    for (int k = 0; k < 4; k++) {
        int r;
        do {
            r = rand() % 4;
        } while (used[r]);
        used[r] = 1;
        order[k] = r;
    }

    bit64 d_x[5] = {0};
    bit64 faulty_tag[2] = {0};
    bit64 tag1[2];
    int flag = 0;

    // ---- try first 3 random guesses ----
    for (int m = 0; m < 3; m++) {
        bit64 val = L[order[m]];

        d_x[3] = (((val & 0x02) >> 1) << (63 - j));
        d_x[4] = ((val & 0x01) << (63 - j));

        linear(d_x);

        faulty_tag[0] = tag[0] ^ d_x[3];
        faulty_tag[1] = tag[1] ^ d_x[4];

        faulty_decryption(associated_data_text, nonce, key,
                          plaintext, ciphertext, tag1,
                          faulty_tag, &flag, i, j);

        if (flag == 1) {
            b[0] = (val >> 1) & 0x01;
            b[1] = val & 0x01;
            return;
        }
    }

    // ---- if none succeeded → take last remaining ----
    bit64 val = L[order[3]];
    b[0] = (val >> 1) & 0x01;
    b[1] = val & 0x01;
}

void online_phase_attack(bit64 associated_data_text[], bit64 nonce[2], bit64 key[2], bit64 plaintext[], bit64 ciphertext[], bit64 tag[2], bit d_table[64][5][2]){
	int j = 0;
  	bit b[2];
  
	/* Tow LSB Difference for Fifth, Fourth and Third Row*/  
   	for(j = 0; j < 64; j++){
      bit_dif(associated_data_text, nonce, key, plaintext, ciphertext, tag, 4, j, b);
      d_table[j][4][0] = b[0];
      d_table[j][4][1] = b[1];
      
      d_table[j][3][0] = b[0]; 		// fourth row
      d_table[j][3][1] = 1;
      
      d_table[j][2][0] = 1;			// third row
      d_table[j][2][1] = 0;
    }
    

 	/* Tow LSB Difference for First Row*/  
	for(j = 0; j < 64; j++){
    	bit64 d_x[5] = {0};
    	bit64 faulty_tag[2] = {0};
    	bit64 tag1[2];
    	int flag = 0;

    	int b = d_table[j][4][1] ^ 1;

		// pick one guess for first bit
		int guess0 = rand() % 2;
		int guess1 = b;

		d_x[3] = (bit64)(guess0) << (63 - j);;
		d_x[4] = (bit64)(guess1) << (63 - j);

		linear(d_x);

		faulty_tag[0] = tag[0] ^ d_x[3];
		faulty_tag[1] = tag[1] ^ d_x[4];

		faulty_decryption(associated_data_text, nonce, key,
                  			plaintext, ciphertext, tag1,
                  			faulty_tag, &flag, 0, j);

			if(flag == 1){
    			d_table[j][0][0] = guess0;
    			d_table[j][0][1] = guess1;
			}
			else{
    			// flip the first bit
    			d_table[j][0][0] = guess0 ^ 1;
    			d_table[j][0][1] = guess1;  // same b
			}
	}

 	/* Tow LSB Difference for second Row*/
	for(j = 0; j < 64; j++){
    	bit64 d_x[5] = {0};
    	bit64 faulty_tag[2] = {0};
    	bit64 tag1[2];
    	int flag1 = 0;

    	int guess0 = 1;
		int guess1 = rand() % 2;

		d_x[3] = (bit64)(guess0) << (63 - j);;
		d_x[4] = (bit64)(guess1) << (63 - j);

    	linear(d_x);

    	faulty_tag[0] = tag[0] ^ d_x[3];
    	faulty_tag[1] = tag[1] ^ d_x[4];

    	faulty_decryption(associated_data_text, nonce, key,
                      plaintext, ciphertext, tag1,
                      faulty_tag, &flag1, 1, j);

    	if(flag1 == 1){
    		d_table[j][1][0] = guess0;
    		d_table[j][1][1] = guess1;
		}
		else{
    		// flip the first bit
    		d_table[j][1][0] = guess0;
    		d_table[j][1][1] = guess1^1;
		}
	}
 
}

int main(){  
  	srand(time(NULL));
  	bit64 nonce[2] = { 0x0000000000000001, 0x0000000000000002 };
  	bit64 associated_data_text[] = { 0x787878, 0x878787, 0x09090 };
  	bit64 key[2] = { 0x0,0x0 };
  	bit64 plaintext[] = { 0x1234567890abcdef, 0xabcdef1234567890 };
  	
  	bit64 plaintext1[2] = { 0 };
  	bit64 ciphertext[2] = { 0 };
  	bit64 ciphertextdecrypt[2] = {0};
  	bit64 tag[2] = {0}, tag1[2] = {0};

  	encryption(associated_data_text, nonce, key, plaintext, ciphertext, tag);			// Call Encryption Oracle to get (C, T)
  
  
  /* construction Table D  */
  	int N = 1000;
  	int f_call[N];
  	for(int count = 0; count < N; count++){ 
  		faulty_calls = 0;
  		bit online_table[64][5][2]={0};  
  		online_phase_attack(associated_data_text, nonce, key, plaintext1, ciphertext, tag, online_table);
  		f_call[count] = faulty_calls;
  		//print_d_table(online_table);
  		//printf("Total faulty_decryption calls = %lld\n", faulty_calls);
	}
	int sum = 0;
	float avg;
  	for(int i = 0; i < N; i++){
  		printf("%d, ",f_call[i]);
  		sum = sum + f_call[i];
	}
	avg = (float)sum / N;
	
	printf("%f",avg);
}
