#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
#include "function_decryption.h"
#include <time.h>

#include <stdint.h>

void sort3(int a[3]) {
    int t;

    if(a[0] > a[1]) { t=a[0]; a[0]=a[1]; a[1]=t; }
    if(a[1] > a[2]) { t=a[1]; a[1]=a[2]; a[2]=t; }
    if(a[0] > a[1]) { t=a[0]; a[0]=a[1]; a[1]=t; }
}

int locate_fault(uint32_t diff[4]) {

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

int main() {

    uint32_t state[4];
    uint32_t s_copy[4];
    uint32_t correct[4];
    uint32_t faulty[4];
    uint32_t diff[4];

    uint32_t round_keys[1][4];

    int reg = 3; 
    int k;

    srand(time(NULL));

    // -----------------------------
    // Generate random state
    // -----------------------------
    for(int i=0;i<4;i++)
        state[i] = rand();

    // -----------------------------
    // Generate random round keys
    // -----------------------------
    for(int i=0;i<4;i++)
        round_keys[0][i] = rand();

    // -----------------------------
    // Choose random fault position
    // -----------------------------
    k   = rand() % 32;     // which bit

    printf("Fault injected at register %d bit %d\n\n", reg, k);

    // copy state
    for(int i=0;i<4;i++)
        s_copy[i] = state[i];

    // =============================
    // Correct computation
    // =============================
    correct[0] = linear(0, state[0]);
    correct[1] = linear(0, state[1]);
    correct[2] = linear(0, state[2]);
    correct[3] = linear(0, state[3]);

    sbox_inverse(&correct[0], &correct[1], &correct[2], &correct[3]);

    correct[0] ^= round_keys[0][0];
    correct[1] ^= round_keys[0][1];
    correct[2] ^= round_keys[0][2];
    correct[3] ^= round_keys[0][3];

    // =============================
    // Inject fault
    // =============================
    s_copy[reg] ^= (0x80000000 >> k);

    // =============================
    // Faulty round
    // =============================
    s_copy[0] = linear(0, s_copy[0]);
    s_copy[1] = linear(0, s_copy[1]);
    s_copy[2] = linear(0, s_copy[2]);
    s_copy[3] = linear(0, s_copy[3]);

    sbox_inverse(&s_copy[0], &s_copy[1], &s_copy[2], &s_copy[3]);

    s_copy[0] ^= round_keys[0][0];
    s_copy[1] ^= round_keys[0][1];
    s_copy[2] ^= round_keys[0][2];
    s_copy[3] ^= round_keys[0][3];

    for(int i=0;i<4;i++)
        faulty[i] = s_copy[i];

    // =============================
    // Compute output difference
    // =============================
    for(int i=0;i<4;i++)
        diff[i] = correct[i] ^ faulty[i];
    
    int c = locate_fault(diff);
    //printf("%d",c);

    if(c == k)
        printf("Fault position = %d is identified\n", c);
    else
        printf("ERROR\n");
    
    return 0;
}
