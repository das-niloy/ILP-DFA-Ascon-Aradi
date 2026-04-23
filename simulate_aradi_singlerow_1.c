#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include "function_decryption.h"

/* -----------------------------
   Utility: check new position
----------------------------- */
int is_new_position(int pos, int used_pos[]) {
    return !used_pos[pos];
}

/* -----------------------------
   Locate fault position
----------------------------- */
void sort3(int a[3]) {
    int t;
    if(a[0] > a[1]) { t=a[0]; a[0]=a[1]; a[1]=t; }
    if(a[1] > a[2]) { t=a[1]; a[1]=a[2]; a[2]=t; }
    if(a[0] > a[1]) { t=a[0]; a[0]=a[1]; a[1]=t; }
}

int locate_fault(uint32_t diff[4]) {

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
            t[1] = (c + 5) % 16;
            t[2] = 16 + ((c + 8) % 16);
        } else {
            t[0] = c;
            t[1] = 16 + ((c + 5) % 16);
            t[2] = (c + 2) % 16;
        }

        sort3(t);

        if(t[0] == obs[0] && t[1] == obs[1] && t[2] == obs[2])
            return c;
    }
    return -1;
}

/* -----------------------------
   Main experiment logic
----------------------------- */
int online_phase2(uint32_t ciphertext[4], uint32_t key[8],
                  uint32_t plaintext[4], uint8_t O[4][32][4],
                  int *distinct_used_total, int reg) {

    uint32_t faulty_plaintext[4];

    int covered[32] = {0};
    int covered_count = 0;

    int used_pos[32] = {0};
    int distinct_used = 0;

    int total_faults = 0;

    while(covered_count < 32){

        int k = rand() % 32;
        total_faults++;

        faulty_decryption_ARADI(ciphertext, key, faulty_plaintext, reg, k);

        uint32_t delta_p[4];
        for(int i = 0; i < 4; i++)
            delta_p[i] = plaintext[i] ^ faulty_plaintext[i];

        int pos = locate_fault(delta_p);
        if(pos == -1)
            continue;

        // skip if already used
        if(!is_new_position(pos, used_pos))
            continue;

        int indices[3];

        if(pos < 16){
            indices[0] = pos;
            indices[1] = (5 + pos) % 16;
            indices[2] = 16 + ((8 + pos) % 16);
        } else {
            indices[0] = pos;
            indices[1] = 16 + ((5 + pos) % 16);
            indices[2] = (2 + pos) % 16;
        }

        // check usefulness
        int useful = 0;
        for(int i = 0; i < 3; i++){
            if(!covered[indices[i]]){
                useful = 1;
                break;
            }
        }

        if(!useful)
            continue;

        // accept position
        used_pos[pos] = 1;
        distinct_used++;

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

    *distinct_used_total = distinct_used;
    return total_faults;
}

/* -----------------------------
   Driver
----------------------------- */
int main(){

    srand(time(NULL));

    uint32_t key[8] = {
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c
    };

    uint32_t plaintext[4] = {0,0,0,0};
    uint32_t ciphertext[4] = {
        0x3f09abf4, 0x00e3bd74, 0x03260def, 0xb7c53912
    };

    uint8_t O[4][32][4];

    int runs = 1000;

    int results_faults[1000];
    int results_distinct[1000];

    double avg_faults = 0;
    double avg_distinct = 0;

    for(int i = 0; i < runs; i++){

        // reset O
        for(int r = 0; r < 4; r++)
            for(int c = 0; c < 32; c++)
                for(int p = 0; p < 4; p++)
                    O[r][c][p] = 0;

        int distinct_used = 0;

        int total_faults =
            online_phase2(ciphertext, key, plaintext, O,
                          &distinct_used, 0);

        results_faults[i] = total_faults;
        results_distinct[i] = distinct_used;

        avg_faults += total_faults;
        avg_distinct += distinct_used;
    }

    avg_faults /= runs;
    avg_distinct /= runs;

    FILE *fp = fopen("results_singlerow.txt", "w");

    fprintf(fp, "Fault counts:\n[");
    for(int i = 0; i < runs; i++){
        fprintf(fp, "%d", results_faults[i]);
        if(i != runs-1) fprintf(fp, ", ");
    }
    fprintf(fp, "]\n\n");

    fprintf(fp, "Distinct positions:\n[");
    for(int i = 0; i < runs; i++){
        fprintf(fp, "%d", results_distinct[i]);
        if(i != runs-1) fprintf(fp, ", ");
    }
    fprintf(fp, "]\n\n");

    fprintf(fp, "Average total faults = %.2f\n", avg_faults);
    fprintf(fp, "Average distinct positions = %.2f\n", avg_distinct);

    fclose(fp);

    return 0;
}
