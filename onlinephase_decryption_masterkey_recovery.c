#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include "function_decryption.h"

int main(){
    uint32_t key[8] = { 0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 
                       0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c };
    uint32_t plaintext[4] = { 0x00000000, 0x00000000, 0x00000000, 0x00000000 };
    uint32_t ciphertext[4] = { 0x3f09abf4, 0x00e3bd74, 0x03260def, 0xb7c53912 };
    uint32_t subkey_0[4], subkey_1[4];
    
    // Construct Offline Table 
    uint8_t P_sbox[4][16][2]={0};
    uint8_t P_invsbox[4][16][2]={0};
    precomputaion(P_sbox, P_invsbox);

    // Construct Online Table
    uint8_t O[4][32][4]={0};
    online_phase(ciphertext, key, plaintext, O);
    
    // 0-Th Sub-key
    uint32_t state[4] = {0};
    state_recovery(O, P_invsbox, state);  
    sbox_inverse(&state[0], &state[1], &state[2], &state[3]);
    for(int i = 0; i < 4; i++){
        subkey_0[i] = plaintext[i] ^ state[i];
    }
    print_hex(subkey_0,4);
    
    // One round encryption
    uint32_t state1[4] = {0};
    for(int i = 0; i < 4; i++){
        state1[i] = plaintext[i] ^ subkey_0[i];
    }
    sbox(&state1[0], &state1[1], &state1[2], &state1[3]);
    state1[0] = linear(0, state1[0]);
    state1[1] = linear(0, state1[1]);
    state1[2] = linear(0, state1[2]);
    state1[3] = linear(0, state1[3]);

    
    // Construct Online Table
    uint8_t O1[4][32][4]={0};
    online_phase1(ciphertext, key, state1, O1, subkey_0);
    
    // 1-Th Sub-key
    uint32_t state2[4] = {0};
    state_recovery(O1, P_invsbox, state2);  
    sbox_inverse(&state2[0], &state2[1], &state2[2], &state2[3]);
    for(int i = 0; i < 4; i++){
        subkey_1[i] = state1[i] ^ state2[i];
    }
    print_hex(subkey_1,4);
    
    // Master Key
    uint32_t master_key[8];
    for(int i = 0; i < 4; i++)
        master_key[i] = subkey_0[i];
    
    uint32_t state3[4] = { subkey_1[0], subkey_1[2], subkey_1[1], subkey_1[3] };
    m0_inv(state3[0], state3[1], &master_key[4], &master_key[5]);
    m1_inv(state3[2], state3[3], &master_key[6], &master_key[7]);
    
    print_hex(master_key, 8);
}

    /*
    for(int i = 0; i < 16; i++){
        for( int j = 0; j < 4; j++){
            printf("%d%d\t", P_invsbox[j][i][0], P_invsbox[j][i][1]);
        }
        printf("\n");
    }
    */
  /*
    for(int i = 0; i < 32; i++){
        for( int j = 0; j < 4; j++){
            printf("%d%d\t", O[j][i][2], O[j][i][3]);
        }
        printf("\n");
    }
    */
    
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
