#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include "function_encryption.h"

int main(){
    uint32_t key[8] = {0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 
                       0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c};
    uint32_t plaintext[4] = {0x00000000, 0x00000000, 0x00000000, 0x00000000};
    uint32_t ciphertext[4];
    
    uint8_t F[4][16][2]={0};    
    precomputaion(F);
    
    encryption_ARADI(plaintext, key, ciphertext);
    //print_hex(ciphertext, 4);    
    
    // Sub-Key Recovery (Last Round)
    
    uint8_t G[4][32][4]={0};
    online_phase15(plaintext, key, ciphertext, G);
    
    uint32_t state_15[4] = {0};
    staterecovery(G, F, state_15);
    //print_hex(state_15,4);
    
    uint32_t copystate_15[4] = {0};
    for(int i = 0; i < 4; i++)
        copystate_15[i] = state_15[i];
       
    uint32_t subkey16[4] = {0};
    sbox(&state_15[0], &state_15[1], &state_15[2], &state_15[3]);
    for (int j = 0; j < 4; j++) {
        state_15[j] = linear(3, state_15[j]);
        subkey16[j] = state_15[j] ^ ciphertext[j];
    }
    print_hex(subkey16,4);    
    
    // Sub-Key Recovery (Second Last Round)
    
    uint8_t G0[4][32][4]={0};
    online_phase14(plaintext, key, ciphertext, G0, subkey16);
    
    uint32_t state_14[4] = {0};
    staterecovery(G0, F, state_14);
    //print_hex(state_14,4);
    
    uint32_t subkey15[4] = {0};
    sbox(&state_14[0], &state_14[1], &state_14[2], &state_14[3]);
    for (int j = 0; j < 4; j++) {
        state_14[j] = linear(2, state_14[j]);
        subkey15[j] = copystate_15[j] ^ state_14[j];
    }
    print_hex(subkey15,4);
}

/*
Subkey 16
[['1', '0', '1', '0', '0', '1', '0', '0', '0', '1', '0', '0', '0', '0', '1', '1', 
  '0', '0', '0', '0', '0', '1', '0', '1', '0', '0', '1', '1', '1', '0', '1', '1'],
 ['0', '1', '1', '0', '1', '0', '0', '1', '0', '0', '1', '1', '0', '0', '1', '0',
  '0', '0', '1', '0', '1', '0', '1', '0', '1', '0', '0', '0', '1', '1', '1', '0'],
 ['1', '1', '1', '0', '1', '0', '0', '0', '1', '0', '1', '0', '1', '0', '1', '1',
  '1', '1', '1', '0', '1', '1', '0', '1', '0', '0', '1', '1', '1', '1', '1', '1'],
 ['0', '1', '0', '0', '0', '0', '0', '1', '1', '1', '0', '0', '1', '1', '1', '1',
  '0', '0', '0', '0', '1', '1', '0', '0', '1', '0', '1', '0', '1', '0', '0', '0']]

Subkey 15

[['0', '1', '1', '1', '0', '0', '0', '1', '1', '1', '0', '0', '0', '1', '0', '1',
  '1', '1', '1', '0', '0', '0', '0', '0', '0', '1', '0', '0', '0', '1', '1', '0'],
 ['1', '0', '0', '0', '1', '0', '1', '0', '1', '0', '1', '1', '1', '0', '0', '1',
  '1', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', '0', '0', '1', '0', '1'],
 ['1', '1', '0', '1', '1', '0', '0', '0', '1', '1', '1', '1', '1', '0', '0', '0',
  '0', '0', '0', '0', '1', '0', '1', '0', '1', '0', '1', '1', '0', '1', '1', '0'],
 ['1', '0', '1', '1', '0', '1', '1', '1', '1', '1', '0', '1', '1', '1', '1', '1',
  '0', '0', '0', '0', '0', '0', '0', '1', '0', '0', '0', '1', '1', '0', '0', '1']]

*/










    /*    
    for (int i = 0; i < 32; i++){
        for (int j = 0; j < 4; j++){
          printf("%d%d\t", G[j][i][2], G[j][i][3]);
        }
        printf("\n");
    }
    for (int i = 0; i < 16; i++){
        for (int j = 0; j < 4; j++){
          printf("%d%d\t", F[j][i][0], F[j][i][1]);
        }
        printf("\n");
    }
    */
