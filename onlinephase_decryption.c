#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

typedef uint64_t bit64;
typedef uint8_t bit;

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

/* Construct Table D:  Required Tools Faulty Oracle*/

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

void bit_dif(bit64 associated_data_text[], bit64 nonce[2], bit64 key[2], bit64 plaintext[], bit64 ciphertext[], bit64 tag[2], int i, int j, bit b[2]){
  bit64 L[3] = { 0x0000000000000001, 0x0000000000000002, 0x0000000000000003 };
  bit64 d_x[5] = {0};
  bit64 faulty_tag[2] = {0};
  bit64 tag1[2];
  int flag = 0;
  for (int m = 0; m < 3; m++){
    d_x[3] = (((L[m] & 0x02) >> 1 ) << (63-j));
    d_x[4] = ((L[m] & 0x01) << (63-j));
    linear(d_x);
    faulty_tag[0] = tag[0] ^ d_x[3];
    faulty_tag[1] = tag[1] ^ d_x[4];
    faulty_decryption (associated_data_text, nonce, key, plaintext, ciphertext, tag1, faulty_tag, &flag, i, j);
    if (flag == 1){
      b[0] = (L[m] >> 1) & 0x01;
      b[1] = L[m] & 0x01;
      break;
    }
    else {
      b[0] = 0;
      b[1] = 0;
    }
  }
}

void online_phase_attack(bit64 associated_data_text[], bit64 nonce[2], bit64 key[2], bit64 plaintext[], bit64 ciphertext[], bit64 tag[2], bit d_table[64][5][2]){
  int j = 0;
  bit b[2];
  
  /* Tow LSB Difference for Fifth, Fourth and Third Row*/
  
   for(j = 0; j < 64; j++){
      bit_dif(associated_data_text, nonce, key, plaintext, ciphertext, tag, 4, j, b);
      d_table[j][4][0] = b[0];
      d_table[j][4][1] = b[1];
      d_table[j][3][0] = b[0];
      d_table[j][3][1] = 1;
      d_table[j][2][0] = 1;
      d_table[j][2][1] = 0;
    }
    
  /* Tow LSB Difference for First Row*/
  
  for(j = 0; j < 64; j++){
    bit64 d_x[5] = {0};
    bit64 faulty_tag[2] = {0};
    bit64 tag1[2];
    int flag = 0;

    d_x[3] = 0;
    d_x[4] = (bit64)(d_table[j][4][1]^1)<<(63-j);

    linear(d_x);
    faulty_tag[0] = tag[0] ^ d_x[3];
    faulty_tag[1] = tag[1] ^ d_x[4];

    faulty_decryption (associated_data_text, nonce, key, plaintext, ciphertext, tag1, faulty_tag, &flag, 0, j);

    if (flag == 1){
      d_table[j][0][0] = 0;
      d_table[j][0][1] = d_table[j][4][1]^1;
    }
    else {
      d_table[j][0][0] = 1;
      d_table[j][0][1] = d_table[j][4][1]^1;
    }
  }
    
  /* Tow LSB Difference for Second Row*/
  
  for(j = 0; j < 64; j++){
    bit64 d_x[5] = {0};
    bit64 faulty_tag[2] = {0};
    bit64 tag1[2];
    int flag1 = 0;
    
    d_x[3] = (bit64)(0x0000000000000001)<<(63-j);
    d_x[4] = 0;

    linear(d_x);
    faulty_tag[0] = tag[0] ^ d_x[3];
    faulty_tag[1] = tag[1] ^ d_x[4];

    faulty_decryption (associated_data_text, nonce, key, plaintext, ciphertext, tag1, faulty_tag, &flag1, 1, j);

    if (flag1 == 1){
    d_table[j][1][0] = 1;
    d_table[j][1][1] = 0;
    }
    else {
    d_table[j][1][0] = 1;
    d_table[j][1][1] = 1;
    }
  }  
}

int main(){  
  bit64 nonce[2] = { 0x0000000000000001, 0x0000000000000002 };
  bit64 associated_data_text[] = { 0x787878, 0x878787, 0x09090 };
  bit64 key[2] = { 0 };
  bit64 plaintext[] = { 0x1234567890abcdef, 0xabcdef1234567890 };
  
  bit64 plaintext1[2] = { 0 };
  bit64 ciphertext[2] = { 0 };
  bit64 ciphertextdecrypt[2] = {0};
  bit64 tag[2] = {0}, tag1[2] = {0};

  encryption(associated_data_text, nonce, key, plaintext, ciphertext, tag);                   // Call Encryption Oracle to get (C, T)
  
  /* construction Table D  */
  
  bit d_table[64][5][2]={0};  
  online_phase_attack(associated_data_text, nonce, key, plaintext1, ciphertext, tag, d_table);
  print_d_table(d_table);
}
