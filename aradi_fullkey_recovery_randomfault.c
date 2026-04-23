#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include <time.h>
#include <stdlib.h>
#include "function_decryption.h"

void sort3(int a[3]) {
    int t;

    if(a[0] > a[1]) { t=a[0]; a[0]=a[1]; a[1]=t; }
    if(a[1] > a[2]) { t=a[1]; a[1]=a[2]; a[2]=t; }
    if(a[0] > a[1]) { t=a[0]; a[0]=a[1]; a[1]=t; }
}

int is_new_position(int pos, int found_pos[], int count) {
    for(int i = 0; i < count; i++) {
        if(found_pos[i] == pos)
            return 0;
    }
    return 1;
}

int locate_fault0(uint32_t diff[4]) {

    int col[3];
    int count = 0;

    for(int b = 0; b < 32; b++) {

        int active = 0;

        for(int r = 0; r < 4; r++) {
            if(diff[r] & (0x80000000 >> b)) {
                active = 1;
                break;
            }
        }

        if(active) {
            if(count < 3)
                col[count] = b;

            count++;
        }
    }

    if(count != 3)
        return -1;

    int x = col[0];
    int y = col[1];
    int z = col[2];

    //printf("Triplet = (%d,%d,%d)\n",x,y,z);

    int obs[3] = {x,y,z};
    sort3(obs);

    for(int c = 0; c < 32; c++) {
      int t[3];

      if(c < 16) {
        t[0] = c;
        t[1] = (c+5)%16;
        t[2] = 16 + ((8+c)%16);
      }
      else {
        t[0] = c;
        t[1] = 16 + ((c+5)%16);
        t[2] = (2+c)%16;
      }

      sort3(t);

      if(t[0]==obs[0] && t[1]==obs[1] && t[2]==obs[2])
        return c;
    }
    return -1;
}

void online_phase_random(uint32_t ciphertext[4], uint32_t key[8],
                   uint32_t plaintext[4], uint8_t O[4][32][4]) {

    uint32_t faulty_plaintext[4];
    
    for(int reg = 0; reg < 4; reg += 3){

        int covered[32] = {0};
        int covered_count = 0;
        int total_faults = 0;          // total injections

        while(covered_count < 32){

            int k = rand() % 32;

            total_faults++;   //count every fault injection

            faulty_decryption_ARADI(ciphertext, key, faulty_plaintext, reg, k);

            uint32_t delta_p[4];
            for(int i = 0; i < 4; i++){
                delta_p[i] = plaintext[i] ^ faulty_plaintext[i];
            }

            int pos = locate_fault0(delta_p);
            if(pos == -1)
                continue;

            int indices[3];

            if(pos < 16){
                indices[0] = pos;
                indices[1] = (5 + pos) % 16;
                indices[2] = 16 + ((8 + pos) % 16);
            }
            else{
                indices[0] = pos;
                indices[1] = 16 + ((5 + pos) % 16);
                indices[2] = (2 + pos) % 16;
            }

            // check usefulness (adds new coverage)
            int useful = 0;
            for(int i = 0; i < 3; i++){
                if(!covered[indices[i]]){
                    useful = 1;
                    break;
                }
            }

            if(!useful)
                continue;

            // update coverage
            for(int i = 0; i < 3; i++){
                int c = indices[i];

                if(!covered[c]){
                    for(int p = 0; p < 4; p++){
                        O[reg][c][p] =
                            (delta_p[p] >> (32 - (c + 1))) & 1;
                    }
                    covered[c] = 1;
                    covered_count++;
                }
            }		
        }
        printf("faulty oracle calls for %d register: %d\n",reg,total_faults);
    }

    // post-processing (unchanged)
    for(int i = 0; i < 32; i++){
        O[2][i][2] = 1;
        O[2][i][3] = O[3][i][0];

        O[1][i][2] = O[0][i][2];
        O[1][i][3] = (O[0][i][2] & (O[3][i][0] ^ O[3][i][2])) ^ O[0][i][1];
    }
}

int locate_fault1(uint32_t diff[4]) {

    int col[3], count = 0;

    for(int b = 0; b < 32; b++) {
        int active = 0;
        for(int r = 0; r < 4; r++) {
            if(diff[r] & (0x80000000 >> b)) {
                active = 1;
                break;
            }
        }
        if(active) {
            if(count < 3) col[count] = b;
            count++;
        }
    }

    if(count != 3)
        return -1;

    int obs[3] = {col[0], col[1], col[2]};
    sort3(obs);

    for(int c = 0; c < 32; c++) {
        int t[3];

        if(c < 16) {
            t[0] = c;
            t[1] = (c + 6) % 16;
            t[2] = 16 + ((c + 7) % 16);
        } else {
            t[0] = c;
            t[1] = 16 + ((c + 6) % 16);
            t[2] = (c + 5) % 16;
        }

        sort3(t);

        if(t[0] == obs[0] && t[1] == obs[1] && t[2] == obs[2])
            return c;
    }
    return -1;
}

void online_phase1_random(uint32_t ciphertext[4], uint32_t key[8],
                   uint32_t plaintext[4], uint8_t O[4][32][4], uint32_t subkey[4]) {

    uint32_t faulty_plaintext[4];
 
    for(int reg = 0; reg < 4; reg += 3){

        int covered[32] = {0};
        int covered_count = 0;
        int total_faults = 0;          // total injections

        while(covered_count < 32){

            int k = rand() % 32;

            total_faults++;   //count every fault injection

            faulty_decryption1_ARADI(ciphertext, key, faulty_plaintext, reg, k);
            uint32_t state1[4] = {0};
		    for(int i = 0; i < 4; i++){
		        state1[i] = faulty_plaintext[i] ^ subkey[i];
		    }
		    sbox(&state1[0], &state1[1], &state1[2], &state1[3]);
		    state1[0] = linear(0, state1[0]);
		    state1[1] = linear(0, state1[1]);
		    state1[2] = linear(0, state1[2]);
		    state1[3] = linear(0, state1[3]);
		    
		    uint32_t delta_p[4];
		    for(int i = 0; i < 4; i++){
		      delta_p[i] = plaintext[i] ^ state1[i];
		    }

            int pos = locate_fault1(delta_p);
            if(pos == -1)
                continue;

            int indices[3];

		    if(pos < 16){
		        indices[0] = pos;
		        indices[1] = (6 + pos) % 16;
		        indices[2] = 16 + ((7 + pos) % 16);
		    } else {
		        indices[0] = pos;
		        indices[1] = 16 + ((6 + pos) % 16);
		        indices[2] = (5 + pos) % 16;
		    }
			//printf("%d\n",pos);
            // check usefulness (adds new coverage)
            int useful = 0;
            for(int i = 0; i < 3; i++){
                if(!covered[indices[i]]){
                    useful = 1;
                    break;
                }
            }

            if(!useful)
                continue;

            // update coverage
            for(int i = 0; i < 3; i++){
                int c = indices[i];

                if(!covered[c]){
                    for(int p = 0; p < 4; p++){
                        O[reg][c][p] = (delta_p[p] >> (32 - (c + 1))) & 1;
                    }
                    covered[c] = 1;
                    covered_count++;
                }
            }		
        }
        printf("faulty oracle calls for %d register: %d\n",reg,total_faults);
    }

    // post-processing (unchanged)
    for(int i = 0; i < 32; i++){
        O[2][i][2] = 1;
        O[2][i][3] = O[3][i][0];

        O[1][i][2] = O[0][i][2];
        O[1][i][3] = (O[0][i][2] & (O[3][i][0] ^ O[3][i][2])) ^ O[0][i][1];
    }
}


int main(){

    srand(time(NULL));  // initialize once

    uint32_t key[8] = { 0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
                        0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c };

    uint32_t plaintext[4] = {0,0,0,0};
    uint32_t ciphertext[4] = { 0x3f09abf4, 0x00e3bd74, 0x03260def, 0xb7c53912 };
    uint32_t subkey_0[4], subkey_1[4];


 	// Construct Offline Table 
    uint8_t P_sbox[4][16][2]={0};
    uint8_t P_invsbox[4][16][2]={0};
    precomputaion(P_sbox, P_invsbox);

    // Construct Online Table
    uint8_t O[4][32][4]={0};
    online_phase_random(ciphertext, key, plaintext, O);
    
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
    online_phase1_random(ciphertext, key, state1, O1, subkey_0);
    
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
    return 0;
}
