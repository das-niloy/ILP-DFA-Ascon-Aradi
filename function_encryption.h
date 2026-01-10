// Utility Functions

uint16_t rotate16(uint16_t val, int rot) {
    return ((val << rot) | (val >> (16 - rot))) & 0xFFFF;
}

uint32_t rotate32(uint32_t val, int rot) {
    return ((val << rot) | (val >> (32 - rot))) & 0xFFFFFFFF;
}

void print_hex(uint32_t* arr, int len) {
    for (int i = 0; i < len; i++) {
        printf("0x%.8x\t", arr[i]);
    }
    printf("\n");
}

// S-box Functions

void sbox(uint32_t* w, uint32_t* x, uint32_t* y, uint32_t* z) {
    *x ^= (*w & *y);
    *z ^= (*x & *y);
    *y ^= (*w & *z);
    *w ^= (*x & *z);
}

void sbox_inverse(uint32_t* w, uint32_t* x, uint32_t* y, uint32_t* z) {
    *w ^= (*x & *z);
    *y ^= (*w & *z);
    *z ^= (*x & *y);
    *x ^= (*w & *y);
}

// Linear Map Functions

uint32_t linear(int j, uint32_t x) {
    int a[4] = {11, 10, 9, 8};
    int b[4] = {8, 9, 4, 9};
    int c[4] = {14, 11, 14, 7};
    
    uint16_t u = (x >> 16) & 0xFFFF;
    uint16_t l = x & 0xFFFF;
    
    uint16_t s0 = rotate16(u, a[j]);
    uint16_t t0 = rotate16(l, a[j]);
    uint16_t s1 = rotate16(u, b[j]);
    uint16_t t1 = rotate16(l, c[j]);
    
    u ^= s0 ^ t1;
    l ^= t0 ^ s1;
    
    return ((u << 16) | l) & 0xFFFFFFFF;
}

// M0 and M1 Functions

void m0(uint32_t x, uint32_t y, uint32_t* out1, uint32_t* out2) {
    *out1 = rotate32(x, 1) ^ y;
    *out2 = rotate32(y, 3) ^ rotate32(x, 1) ^ y;
}

void m1(uint32_t x, uint32_t y, uint32_t* out1, uint32_t* out2) {
    *out1 = rotate32(x, 9) ^ y;
    *out2 = rotate32(y, 28) ^ rotate32(x, 9) ^ y;
}

// Key Schedule Functions

void keyschedule(uint32_t* key, int i, uint32_t* ki, uint32_t* ki2) {
    uint32_t t0, t1, t2, t3, t4, t5, t6, t7;
    
    m0(key[0], key[1], &t0, &t1);
    m1(key[2], key[3], &t2, &t3);
    m0(key[4], key[5], &t4, &t5);
    m1(key[6], key[7], &t6, &t7);
    
    ki[0] = t0; ki[1] = t2; ki[2] = t1; ki[3] = t3;
    ki[4] = t4; ki[5] = t6; ki[6] = t5; ki[7] = t7 ^ i;
    
    m0(ki[0], ki[1], &t0, &t1);
    m1(ki[2], ki[3], &t2, &t3);
    m0(ki[4], ki[5], &t4, &t5);
    m1(ki[6], ki[7], &t6, &t7);
    
    ki2[0] = t0; ki2[1] = t4; ki2[2] = t2; ki2[3] = t6;
    ki2[4] = t1; ki2[5] = t5; ki2[6] = t3; ki2[7] = t7 ^ (i + 1);
}

void roundkeys(uint32_t* key, uint32_t round_keys[17][4]) {
    uint32_t keys[17][8];
    
    // Initial key
    for (int i = 0; i < 8; i++) {
        keys[0][i] = key[i];
    }
    
    // Generate round keys
    for (int i = 1; i < 16; i += 2) {
        keyschedule(keys[i - 1], i - 1, keys[i], keys[i + 1]);
    }
    
    // Extract 4 blocks for each round key
    for (int i = 0; i < 17; i++) {
        for (int j = 0; j < 4; j++) {
            if (i == 0) {
              round_keys[i][j] = key[j];
            } else {
                if (i % 2 == 0) {
                round_keys[i][j] = keys[i][j + 0];  // i even → offset 0
                } else {
                round_keys[i][j] = keys[i][j + 4];  // i odd → offset 4
                }
             }

        }
    }
}

// Encryption and Decryption Functions

void encryption_ARADI(uint32_t* state, uint32_t* key, uint32_t* out) {
    uint32_t round_keys[17][4];
    roundkeys(key, round_keys);
    
    uint32_t w = state[0];
    uint32_t x = state[1];
    uint32_t y = state[2];
    uint32_t z = state[3];
    
    for (int i = 0; i < 16; i++) {
        w ^= round_keys[i][0];
        x ^= round_keys[i][1];
        y ^= round_keys[i][2];
        z ^= round_keys[i][3];
        //printf("0x%x\t0x%x\t0x%x\t0x%x ", w,x,y,z);
        //printf("\n");
        sbox(&w, &x, &y, &z);
        
        int j = i % 4;
        w = linear(j, w);
        x = linear(j, x);
        y = linear(j, y);
        z = linear(j, z);
    }
    
    w ^= round_keys[16][0];
    x ^= round_keys[16][1];
    y ^= round_keys[16][2];
    z ^= round_keys[16][3];
    
    out[0] = w;
    out[1] = x;
    out[2] = y;
    out[3] = z;
    //print_hex(round_keys[15],4);
    //print_hex(round_keys[16],4);
}

void decryption_ARADI(uint32_t* state, uint32_t* key, uint32_t* out) {
    uint32_t round_keys[17][4];
    roundkeys(key, round_keys);
    
    uint32_t w = state[0];
    uint32_t x = state[1];
    uint32_t y = state[2];
    uint32_t z = state[3];
    
    w ^= round_keys[16][0];
    x ^= round_keys[16][1];
    y ^= round_keys[16][2];
    z ^= round_keys[16][3];
    
    for (int i = 15; i >= 0; i--) {
        int j = i % 4;
        
        w = linear(j, w);
        x = linear(j, x);
        y = linear(j, y);
        z = linear(j, z);
        
        sbox_inverse(&w, &x, &y, &z);
        
        w ^= round_keys[i][0];
        x ^= round_keys[i][1];
        y ^= round_keys[i][2];
        z ^= round_keys[i][3];
    }
    
    out[0] = w;
    out[1] = x;
    out[2] = y;
    out[3] = z;
}

// Precomputation Phase (Table F)

uint8_t s_box[16] = {
    0x0, 0x1, 0x2, 0x3,
    0x4, 0xD, 0xF, 0x6,
    0x8, 0xB, 0x5, 0xE,
    0xC, 0x7, 0xA, 0x9
};

uint8_t delta_x[4] = { 0x8, 0x4, 0x2, 0x1 };

void precomputaion(uint8_t F[4][16][2]){
  for (int i = 0; i < 16; i++) {
    for (int j = 0; j < 4; j++) {
        uint8_t x_prime = i ^ delta_x[j];
        uint8_t diff = s_box[x_prime] ^ s_box[i];
        F[j][i][0] = (diff >> 1) & 1;
        F[j][i][1] = diff & 1;
    }
  }
}

// Faulty Encryption Function (at the input of 15 round) 

void faulty_encryption_ARADI_15(uint32_t* state, uint32_t* key, uint32_t* out, int reg, int k) {
    uint32_t round_keys[17][4];
    roundkeys(key, round_keys);
    
    uint32_t S[4] = {state[0], state[1], state[2], state[3]};

    for (int i = 0; i < 15; i++) {
        for (int j = 0; j < 4; j++) {
            S[j] ^= round_keys[i][j];
        }

        sbox(&S[0], &S[1], &S[2], &S[3]);

        int j = i % 4;
        for (int m = 0; m < 4; m++) {
            S[m] = linear(j, S[m]);
        }
    }

    // Inject the fault in the specified register (0=w, 1=x, 2=y, 3=z)
    S[reg] ^= (0x80000000 >> k);

    for (int j = 0; j < 4; j++) {
        S[j] ^= round_keys[15][j];
    }

    sbox(&S[0], &S[1], &S[2], &S[3]);

    for (int j = 0; j < 4; j++) {
        S[j] = linear(3, S[j]);
        S[j] ^= round_keys[16][j];
    }

    for (int j = 0; j < 4; j++) {
        out[j] = S[j];
    }
}


// Online Phase (Table G)
/*
void online_phase0(uint32_t plaintext[4], uint32_t key[8], uint32_t ciphertext[4], uint8_t G[4][32][4]){
    uint32_t faulty_ciphertext[4];
    
    for(int reg = 0; reg < 4; reg++){
        for(int k = 0; k < 32; k++){
            faulty_encryption_ARADI_15(plaintext, key, faulty_ciphertext, reg, k);
            //print_hex(faulty_ciphertext, 4);
            
            uint32_t delta_ciphertext[4];
            for(int i = 0; i < 4; i++){
              delta_ciphertext[i] = ciphertext[i] ^ faulty_ciphertext[i];
            }
            //print_hex(delta_ciphertext, 4);
            
            uint32_t S[4];
                S[0] = linear(3, delta_ciphertext[0]);
                S[1] = linear(3, delta_ciphertext[1]);
                S[2] = linear(3, delta_ciphertext[2]);
                S[3] = linear(3, delta_ciphertext[3]);
            //print_hex(S, 4);
            
            G[reg][k][0] = (S[0] >> (32-(k+1))) & 1;
            G[reg][k][1] = (S[1] >> (32-(k+1))) & 1;
            G[reg][k][2] = (S[2] >> (32-(k+1))) & 1;
            G[reg][k][3] = (S[3] >> (32-(k+1))) & 1;
            
            //printf("%d %d\n", G[3][k][0], G[3][k][1] );
        }
    }
}
*/
void online_phase15(uint32_t plaintext[4], uint32_t key[8], uint32_t ciphertext[4], uint8_t G[4][32][4]){
    uint32_t faulty_ciphertext[4];
    
    for(int reg = 0; reg < 4; reg+=3){
        for(int k = 0; k < 32; k++){
            faulty_encryption_ARADI_15(plaintext, key, faulty_ciphertext, reg, k);
            //print_hex(faulty_ciphertext, 4);
            
            uint32_t delta_ciphertext[4];
            for(int i = 0; i < 4; i++){
              delta_ciphertext[i] = ciphertext[i] ^ faulty_ciphertext[i];
            }
            //print_hex(delta_ciphertext, 4);
            
            uint32_t S[4];
                S[0] = linear(3, delta_ciphertext[0]);
                S[1] = linear(3, delta_ciphertext[1]);
                S[2] = linear(3, delta_ciphertext[2]);
                S[3] = linear(3, delta_ciphertext[3]);
            //print_hex(S, 4);
            
            G[reg][k][0] = (S[0] >> (32-(k+1))) & 1;
            G[reg][k][1] = (S[1] >> (32-(k+1))) & 1;
            G[reg][k][2] = (S[2] >> (32-(k+1))) & 1;
            G[reg][k][3] = (S[3] >> (32-(k+1))) & 1;
            
            //printf("%d %d\n", G[3][k][0], G[3][k][1] );
        }
    }
    
    for(int i = 0; i < 32; i++){
        G[1][i][2] = G[0][i][3] & G[3][i][2];       // y*w
        G[1][i][3] = G[0][i][3];                    // y
        
        G[2][i][3] = G[3][i][0] ^ (G[0][i][3] & G[3][i][2]) ^ G[3][i][2];       // x + w*y + y*w + w
        G[2][i][2] = (G[2][i][3] & G[3][i][2]) ^ 1;                             // (x + w*y + y*w + w)*w + 1
    }
}

// Faulty Encryption Function (at the input of 14 round)

void faulty_encryption_ARADI_14(uint32_t* state, uint32_t* key, uint32_t* out, int reg, int k) {
    uint32_t round_keys[17][4];
    roundkeys(key, round_keys);
    
    uint32_t S[4] = {state[0], state[1], state[2], state[3]};

    for (int i = 0; i < 14; i++) {
        for (int j = 0; j < 4; j++) {
            S[j] ^= round_keys[i][j];
        }

        sbox(&S[0], &S[1], &S[2], &S[3]);

        int j = i % 4;
        for (int m = 0; m < 4; m++) {
            S[m] = linear(j, S[m]);
        }
    }
    
    uint32_t delS[4], copyS[4];
    for(int n = 0; n < 4; n++)
        copyS[n] = S[n];
        
    // Inject the fault in the specified register (0=w, 1=x, 2=y, 3=z)
    S[reg] ^= (0x80000000 >> k);
    
    for(int n = 0; n < 4; n++)
        delS[n] = copyS[n] ^ S[n];
    //print_hex(S, 4);
    //print_hex(copyS, 4);
    //print_hex(delS, 4);
    
    // Round 15
    for (int j = 0; j < 4; j++) {
        S[j] ^= round_keys[14][j];
        copyS[j] ^= round_keys[14][j];
    }
    
    for(int n = 0; n < 4; n++)
        delS[n] = copyS[n] ^ S[n];
    //print_hex(S, 4);
    //print_hex(copyS, 4);
    //print_hex(delS, 4);
    
    sbox(&S[0], &S[1], &S[2], &S[3]);
    sbox(&copyS[0], &copyS[1], &copyS[2], &copyS[3]);
    
    for(int n = 0; n < 4; n++)
        delS[n] = copyS[n] ^ S[n];
    //print_hex(S, 4);
    //print_hex(copyS, 4);
    //print_hex(delS, 4);
    
    for (int j = 0; j < 4; j++) {
        S[j] = linear(2, S[j]);
        copyS[j] = linear(2, copyS[j]);
    }
    for(int n = 0; n < 4; n++)
        delS[n] = copyS[n] ^ S[n];

    
    // Round 16
    for (int j = 0; j < 4; j++) {
        S[j] ^= round_keys[15][j];
        copyS[j] ^= round_keys[15][j];
    }
    for(int n = 0; n < 4; n++)
        delS[n] = copyS[n] ^ S[n];
    //print_hex(S, 4);
    //print_hex(copyS, 4);
    //print_hex(delS, 4);

    sbox(&S[0], &S[1], &S[2], &S[3]);
    sbox(&copyS[0], &copyS[1], &copyS[2], &copyS[3]);
    
    for(int n = 0; n < 4; n++)
        delS[n] = copyS[n] ^ S[n];
    

    for (int j = 0; j < 4; j++) {
        S[j] = linear(3, S[j]);
        copyS[j] = linear(3, copyS[j]);
    }
    for(int n = 0; n < 4; n++)
        delS[n] = copyS[n] ^ S[n];

    // Masking with Last Sub_Key
    for (int j = 0; j < 4; j++) {
        S[j] ^= round_keys[16][j];
        copyS[j] ^= round_keys[16][j];
    }
    for(int n = 0; n < 4; n++)
        delS[n] = copyS[n] ^ S[n];


    for (int j = 0; j < 4; j++) {
        out[j] = S[j];
    }
}

// Online Phase (Table G0)

void online_phase14(uint32_t plaintext[4], uint32_t key[8], uint32_t ciphertext[4], uint8_t G0[4][32][4], uint32_t subkey16[4]){
    uint32_t faulty_ciphertext[4];
    uint32_t S15[4];
    for(int i = 0; i < 4; i++){
        S15[i] = ciphertext[i] ^ subkey16[i];
        S15[i] = linear(3, S15[i]);
    }
    sbox_inverse(&S15[0], &S15[1], &S15[2], &S15[3]);
    
    for(int reg = 0; reg < 4; reg+=3){
    //int reg = 3;
        for(int k = 0; k < 32; k++){
            faulty_encryption_ARADI_14(plaintext, key, faulty_ciphertext, reg, k);
            //print_hex(faulty_ciphertext, 4);
            
            uint32_t faulty_S15[4];
            for(int i = 0; i < 4; i++){
                faulty_S15[i] = faulty_ciphertext[i] ^ subkey16[i];
                faulty_S15[i] = linear(3, faulty_S15[i]);
            }
            sbox_inverse(&faulty_S15[0], &faulty_S15[1], &faulty_S15[2], &faulty_S15[3]);
            
            
            uint32_t delta_S15[4];
            for(int i = 0; i < 4; i++){
              delta_S15[i] = S15[i] ^ faulty_S15[i];
            }
            //print_hex(delta_S15, 4);
            
            uint32_t S[4];
                S[0] = linear(2, delta_S15[0]);
                S[1] = linear(2, delta_S15[1]);
                S[2] = linear(2, delta_S15[2]);
                S[3] = linear(2, delta_S15[3]);
            //print_hex(S, 4);
            
            G0[reg][k][0] = (S[0] >> (32-(k+1))) & 1;
            G0[reg][k][1] = (S[1] >> (32-(k+1))) & 1;
            G0[reg][k][2] = (S[2] >> (32-(k+1))) & 1;
            G0[reg][k][3] = (S[3] >> (32-(k+1))) & 1;
            
            //printf("%d %d", G0[reg][k][2], G0[reg][k][3] );
            //printf("\n");
        }
    }
    
    for(int i = 0; i < 32; i++){
        G0[1][i][2] = G0[0][i][3] & G0[3][i][2];       // y*w
        G0[1][i][3] = G0[0][i][3];                    // y
        
        G0[2][i][3] = G0[3][i][0] ^ (G0[0][i][3] & G0[3][i][2]) ^ G0[3][i][2];       // x + w*y + y*w + w
        G0[2][i][2] = (G0[2][i][3] & G0[3][i][2]) ^ 1;                             // (x + w*y + y*w + w)*w + 1
    }
    
}


void staterecovery(uint8_t G[4][32][4], uint8_t F[4][16][2], uint32_t X[4]){
    uint32_t m_points[32]={0};
    for (int i = 0; i < 32; i++) {        
        for (int j = 0; j < 16; j++) {
          int match = 1;              
          for (int x = 0; x < 4; x++) {
            if (G[x][i][2] != F[x][j][0] || G[x][i][3] != F[x][j][1]){                  
              match = 0; 
              break;  
            }
          }
          if (match) {
          m_points[i] = j;                                           
          break;
          }
        }
    }  
    for (int i = 0; i < 32; i++){
      X[0] |= ((m_points[i] & 0x8) >> 3) << (31 - i);
      X[1] |= ((m_points[i] & 0x4) >> 2) << (31 - i);   
      X[2] |= ((m_points[i] & 0x2) >> 1) << (31 - i); 
      X[3] |= ((m_points[i] & 0x1)) << (31 - i); 
      //printf("%d\n", m_points[i]);
    }
    //print_hex(X, 4);
}

//Key Recovery
void keyrecovery(uint32_t S[4], int round, uint32_t ciphertext[4], uint32_t subkey[4]){
    sbox(&S[0], &S[1], &S[2], &S[3]); 
    for (int m = 0; m < 4; m++) {
        S[m] = linear(round, S[m]);
    }
    for (int m = 0; m < 4; m++){
        subkey[m] = S[m] ^ ciphertext[m];
    }
}

