#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

typedef uint64_t bit64;
typedef uint8_t bit;

bit64 constants[12] = {0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b};

bit64 printx( bit64 x){
  printf("%" PRIX64"\n", x);
  printf("\n");
}

bit64 print_state(bit64 state[5]){
   for(int i = 0; i < 5; i++){
      printf("%" PRIX64"\n", state[i]);
   } 
   printf("\n");
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

void linear_2(bit64 state[2]){
   bit64 temp0, temp1;
   temp0 = rotate(state[0], 10);
   temp1 = rotate(state[0], 17);
   state[0] ^= temp0 ^ temp1;
   temp0 = rotate(state[1], 7);
   temp1 = rotate(state[1], 41);
   state[1] ^= temp0 ^ temp1;
}
void inv_linear_2(bit64 state[2]){
   for(int i = 0; i < 63; i++){
      linear_2(state);
   }
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

/*  Construct Table D:  Required Tools Faulty Oracle   */

void faulty_finalization(bit64 state[5], bit64 key[2], int i, int j){
   state[1] ^= key[0];
   state[2] ^= key[1];
   for (int i = 0; i < 10; i++){
      add_constant(state, i, 12);
      sbox(state);
      linear(state);
   }
   add_constant(state, 10, 12);
   sbox(state);
   
   state[i] = state[i] ^ ( 0x8000000000000000 >> j );            //Injecting Bit-Flip Fault at (i, j)-th position
   
   linear(state);
   add_constant(state, 11, 12);    
   sbox(state);
   linear(state);
   state[3] ^= key[0];
   state[4] ^= key[1];
}

void faulty_encryption(bit64 associated_data_text[], bit64 nonce[], bit64 key[], bit64 plaintext[], bit64 ciphertext[], bit64 f_tag[2], int i, int j){
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
   
   faulty_finalization(state, key, i, j);
   f_tag[0] = state[3];
   f_tag[1] = state[4];
}

void online_phase_attack(bit64 associated_data_text[], bit64 nonce[2], bit64 key[2], bit64 plaintext[], bit64 ciphertext[], bit64 tag[2], bit d_table[64][5][2]){

    int G0[23] = {3, 6, 9, 13, 16, 19, 23, 26, 29, 30, 33, 36, 39, 40, 43, 46, 47, 50, 53, 56, 57, 60, 63};
    int G1[24] = {0, 2, 7, 9, 11, 16, 17, 18, 19, 24, 26, 28, 30, 35, 36, 37, 43, 45, 47, 52, 54, 56, 62, 63};
    int G4[24] = {0, 1, 5, 6, 10, 11, 15, 16, 17, 21, 22, 26, 27, 28, 32, 33, 37, 38, 42, 43, 48, 53, 54, 59};
    
  bit64 del_tag[2];
  bit64 f_tag[2];
  
  /* Tow LSB Difference for First Row */
  
  for(int j = 0; j < 23; j++){      
    faulty_encryption (associated_data_text, nonce, key, plaintext, ciphertext, f_tag, 0, G0[j]);

    for(int k = 0; k < 2; k++)
      del_tag[k] = tag[k] ^ f_tag[k];
      
    inv_linear_2(del_tag);
    
    d_table[G0[j]][0][0] = ((del_tag[0] & ( 0x8000000000000000 >> G0[j] )) >> (63-G0[j])) & 1;
    d_table[(G0[j]+19)%64][0][0] = ((del_tag[0] & ( 0x8000000000000000 >> ((G0[j]+19)%64) )) >> (63-((G0[j]+19)%64))) & 1;
    d_table[((G0[j]+28)%64)][0][0] = ((del_tag[0] & ( 0x8000000000000000 >> ((G0[j]+28)%64) )) >> (63-((G0[j]+28)%64))) & 1;

    d_table[G0[j]][0][1] = ((del_tag[1] & ( 0x8000000000000000 >> G0[j] )) >> (63-G0[j])) & 1;
    d_table[(G0[j]+19)%64][0][1] = ((del_tag[1] & ( 0x8000000000000000 >> ((G0[j]+19)%64) )) >> (63-((G0[j]+19)%64))) & 1;
    d_table[((G0[j]+28)%64)][0][1] = ((del_tag[1] & ( 0x8000000000000000 >> ((G0[j]+28)%64) )) >> (63-((G0[j]+28)%64))) & 1;
  }
  
  /* Tow LSB Difference for Second Row */
  
  for(int j = 0; j < 24; j++){      
    faulty_encryption (associated_data_text, nonce, key, plaintext, ciphertext, f_tag, 1, G1[j]);

    for(int k = 0; k < 2; k++)
      del_tag[k] = tag[k] ^ f_tag[k];

    inv_linear_2(del_tag);

    d_table[G1[j]][1][0] = ((del_tag[0] & ( 0x8000000000000000 >> G1[j] )) >> (63-G1[j])) & 1;
    d_table[(G1[j]+61)%64][1][0] = ((del_tag[0] & ( 0x8000000000000000 >> ((G1[j]+61)%64) )) >> (63-((G1[j]+61)%64))) & 1;
    d_table[((G1[j]+39)%64)][1][0] = ((del_tag[0] & ( 0x8000000000000000 >> ((G1[j]+39)%64) )) >> (63-((G1[j]+39)%64))) & 1;

    d_table[G1[j]][1][1] = ((del_tag[1] & ( 0x8000000000000000 >> G1[j] )) >> (63-G1[j])) & 1;
    d_table[(G1[j]+61)%64][1][1] = ((del_tag[1] & ( 0x8000000000000000 >> ((G1[j]+61)%64) )) >> (63-((G1[j]+61)%64))) & 1;
    d_table[((G1[j]+39)%64)][1][1] = ((del_tag[1] & ( 0x8000000000000000 >> ((G1[j]+39)%64) )) >> (63-((G1[j]+39)%64))) & 1;
  }
  
  /* Tow LSB Difference for Fifth Row */
  
  for(int j = 0; j < 24; j++){      
    faulty_encryption (associated_data_text, nonce, key, plaintext, ciphertext, f_tag, 4, G4[j]);
    
    for(int k = 0; k < 2; k++)
      del_tag[k] = tag[k] ^ f_tag[k];

    inv_linear_2(del_tag);

    d_table[G4[j]][4][0] = ((del_tag[0] & ( 0x8000000000000000 >> G4[j] )) >> (63-G4[j])) & 1;
    d_table[(G4[j]+7)%64][4][0] = ((del_tag[0] & ( 0x8000000000000000 >> ((G4[j]+7)%64) )) >> (63-((G4[j]+7)%64))) & 1;
    d_table[((G4[j]+41)%64)][4][0] = ((del_tag[0] & ( 0x8000000000000000 >> ((G4[j]+41)%64) )) >> (63-((G4[j]+41)%64))) & 1;

    d_table[G4[j]][4][1] = ((del_tag[1] & ( 0x8000000000000000 >> G4[j] )) >> (63-G4[j])) & 1;
    d_table[(G4[j]+7)%64][4][1] = ((del_tag[1] & ( 0x8000000000000000 >> ((G4[j]+7)%64) )) >> (63-((G4[j]+7)%64))) & 1;
    d_table[((G4[j]+41)%64)][4][1] = ((del_tag[1] & ( 0x8000000000000000 >> ((G4[j]+41)%64) )) >> (63-((G4[j]+41)%64))) & 1;
  }
  
  /* Tow LSB Difference for Third and Fourth */
  
  for(int j=0; j<64; j++){
      d_table[j][2][0] = 1;
      d_table[j][2][1] = 0;
      d_table[j][3][0] = d_table[j][4][0];
      d_table[j][3][1] = 1;
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
  
  encryption(associated_data_text, nonce, key, plaintext, ciphertext, tag);          // Call Encryption Oracle to get (C, T) 

  /* construction Table D  */

  bit d_table[64][5][2]={0};
  online_phase_attack(associated_data_text, nonce, key, plaintext, ciphertext, tag, d_table);
  print_d_table(d_table);
}
