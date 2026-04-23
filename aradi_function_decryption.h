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

// M0, M0inverse and M1, M1inverse Functions

void m0(uint32_t x, uint32_t y, uint32_t* out1, uint32_t* out2) {
    *out1 = rotate32(x, 1) ^ y;
    *out2 = rotate32(y, 3) ^ rotate32(x, 1) ^ y;
}

void m1(uint32_t x, uint32_t y, uint32_t* out1, uint32_t* out2) {
    *out1 = rotate32(x, 9) ^ y;
    *out2 = rotate32(y, 28) ^ rotate32(x, 9) ^ y;
}

void m0_inv(uint32_t x, uint32_t y, uint32_t* out1, uint32_t* out2) {
  uint32_t r1, r2, r3;
  r1 = x^y;
  r2 = rotate32(r1, 29);
  r3 = x^r2;
  *out1 = rotate32(r3, 31);
  *out2 = r2;  
}

void m1_inv(uint32_t x, uint32_t y, uint32_t* out1, uint32_t* out2) {
  uint32_t r1, r2, r3;
  r1 = x^y;
  r2 = rotate32(r1, 4);
  r3 = x^r2;
  *out1 = rotate32(r3, 23);
  *out2 = r2;  
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
    // Generate round keys
    uint32_t round_keys[17][4];
    roundkeys(key, round_keys);
    
    // Copying the state in w,x,y,z
    uint32_t w = state[0];
    uint32_t x = state[1];
    uint32_t y = state[2];
    uint32_t z = state[3];
    
    // Round functions 0 to 15
    for (int i = 0; i < 16; i++) {
        w ^= round_keys[i][0];
        x ^= round_keys[i][1];
        y ^= round_keys[i][2];
        z ^= round_keys[i][3];
        
        sbox(&w, &x, &y, &z);
        
        int j = i % 4;
        w = linear(j, w);
        x = linear(j, x);
        y = linear(j, y);
        z = linear(j, z);
    }
    
    // Key Mixing
    w ^= round_keys[16][0];
    x ^= round_keys[16][1];
    y ^= round_keys[16][2];
    z ^= round_keys[16][3];
    
    // Generate ciphertext
    out[0] = w;
    out[1] = x;
    out[2] = y;
    out[3] = z;
    //print_hex(round_keys[15],4);
    //print_hex(round_keys[16],4);
}

void decryption_ARADI(uint32_t* state, uint32_t* key, uint32_t* out) {
    // Generate round keys
    uint32_t round_keys[17][4];
    roundkeys(key, round_keys);
    
    // Copying the state in w,x,y,z
    uint32_t w = state[0];
    uint32_t x = state[1];
    uint32_t y = state[2];
    uint32_t z = state[3];
    
    // Key Mixing
    w ^= round_keys[16][0];
    x ^= round_keys[16][1];
    y ^= round_keys[16][2];
    z ^= round_keys[16][3];
    
    // Round functions 15 to 0
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
    
    // Generate plaintext
    out[0] = w;
    out[1] = x;
    out[2] = y;
    out[3] = z;
}

// Precomputation phase (Table P_sbox and Table P_invsbox)

uint8_t s_box[16] = {
    0x0, 0x1, 0x2, 0x3,
    0x4, 0xD, 0xF, 0x6,
    0x8, 0xB, 0x5, 0xE,
    0xC, 0x7, 0xA, 0x9
};

uint8_t invs_box[16] = {
    0x0, 0x1, 0x2, 0x3,
    0x4, 0xA, 0x7, 0xD,
    0x8, 0xF, 0xE, 0x9,
    0xC, 0x5, 0xB, 0x6
};

uint8_t delta_x[4] = { 0x8, 0x4, 0x2, 0x1 };

void precomputaion(uint8_t P_sbox[4][16][2], uint8_t P_invsbox[4][16][2]) {
  for (int i = 0; i < 16; i++) {
    for (int j = 0; j < 4; j++) {
        uint8_t x_prime = i ^ delta_x[j];
        
        uint8_t diff_sbox = s_box[x_prime] ^ s_box[i];
        uint8_t diff_invsbox = invs_box[x_prime] ^ invs_box[i];
        
        P_sbox[j][i][0] = (diff_sbox >> 1) & 1;
        P_sbox[j][i][1] = diff_sbox & 1;
        
        P_invsbox[j][i][0] = (diff_invsbox >> 1) & 1;
        P_invsbox[j][i][1] = diff_invsbox & 1;
    }
  }
}

// Faulty decryption oracle

void faulty_decryption_ARADI(uint32_t* state, uint32_t* key, uint32_t* out, int reg, int k) {
    // Generate round keys
    uint32_t round_keys[17][4];
    roundkeys(key, round_keys);
    
    // Copying the state
    uint32_t s_copy[4];
    for(int i = 0; i < 4; i++)
      s_copy[i] = state[i];    
    
    // Key Mixing
    s_copy[0] ^= round_keys[16][0];
    s_copy[1] ^= round_keys[16][1];
    s_copy[2] ^= round_keys[16][2];
    s_copy[3] ^= round_keys[16][3];
    
    // Round functions 15 to 1
    for (int i = 15; i >= 1; i--) {
        int j = i % 4;
        
        s_copy[0] = linear(j, s_copy[0]);
        s_copy[1] = linear(j, s_copy[1]);
        s_copy[2] = linear(j, s_copy[2]);
        s_copy[3] = linear(j, s_copy[3]);
        
        sbox_inverse(&s_copy[0], &s_copy[1], &s_copy[2], &s_copy[3]);
        
        s_copy[0] ^= round_keys[i][0];
        s_copy[1] ^= round_keys[i][1];
        s_copy[2] ^= round_keys[i][2];
        s_copy[3] ^= round_keys[i][3];
    }
    
    // Faulty round
    //print_hex(s_copy,4);
    s_copy[reg] ^= (0x80000000 >> k);
    //print_hex(s_copy,4);    
    
    // Round 0
    s_copy[0] = linear(0, s_copy[0]);
    s_copy[1] = linear(0, s_copy[1]);
    s_copy[2] = linear(0, s_copy[2]);
    s_copy[3] = linear(0, s_copy[3]);
    
    sbox_inverse(&s_copy[0], &s_copy[1], &s_copy[2], &s_copy[3]);
    
    s_copy[0] ^= round_keys[0][0];
    s_copy[1] ^= round_keys[0][1];
    s_copy[2] ^= round_keys[0][2];
    s_copy[3] ^= round_keys[0][3];
    
    // Generate plaintext
    out[0] = s_copy[0];
    out[1] = s_copy[1];
    out[2] = s_copy[2];
    out[3] = s_copy[3];
}

// Online phase (Table O)

void online_phase(uint32_t ciphertext[4], uint32_t key[8], uint32_t plaintext[4], uint8_t O[4][32][4]) {
    uint32_t faulty_plaintext[4];
    
    for(int reg = 0; reg < 4; reg += 3){
        for(int k = 0; k < 16; k++){
            faulty_decryption_ARADI(ciphertext, key, faulty_plaintext, reg, k);
            
            uint32_t delta_p[4];
            for(int i = 0; i < 4; i++){
              delta_p[i] = plaintext[i] ^ faulty_plaintext[i];
            }
            //print_hex(delta_ciphertext, 4);
            
            O[reg][k][0] = (delta_p[0] >> (32-(k+1))) & 1;
            O[reg][k][1] = (delta_p[1] >> (32-(k+1))) & 1;
            O[reg][k][2] = (delta_p[2] >> (32-(k+1))) & 1;
            O[reg][k][3] = (delta_p[3] >> (32-(k+1))) & 1;
            
            O[reg][16+(8+k)%16][0] = (delta_p[0] >> (32-(16+(8+k)%16+1))) & 1;
            O[reg][16+(8+k)%16][1] = (delta_p[1] >> (32-(16+(8+k)%16+1))) & 1;
            O[reg][16+(8+k)%16][2] = (delta_p[2] >> (32-(16+(8+k)%16+1))) & 1;
            O[reg][16+(8+k)%16][3] = (delta_p[3] >> (32-(16+(8+k)%16+1))) & 1;
            
            //printf("%d %d\n", G[3][k][0], G[3][k][1] );
        }
    }
    
    for(int i = 0; i < 32; i++){
        O[2][i][2] = 1;       
        O[2][i][3] = O[3][i][0];                    
        
        O[1][i][2] = O[0][i][2];       
        O[1][i][3] = (O[0][i][2] & (O[3][i][0] ^ O[3][i][2])) ^ O[0][i][1];                             
    }
    
}

// Internal State Recovery
void state_recovery(uint8_t G[4][32][4], uint8_t F[4][16][2], uint32_t X[4]) {
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


// Faulty decryption oracle

void faulty_decryption1_ARADI(uint32_t* state, uint32_t* key, uint32_t* out, int reg, int k) {
    // Generate round keys
    uint32_t round_keys[17][4];
    roundkeys(key, round_keys);
    
    // Copying the state
    uint32_t s_copy[4];
    for(int i = 0; i < 4; i++)
      s_copy[i] = state[i];    
    
    // Key Mixing
    s_copy[0] ^= round_keys[16][0];
    s_copy[1] ^= round_keys[16][1];
    s_copy[2] ^= round_keys[16][2];
    s_copy[3] ^= round_keys[16][3];
    
    // Round functions 15 to 2
    for (int i = 15; i >= 2; i--) {
        int j = i % 4;
        
        s_copy[0] = linear(j, s_copy[0]);
        s_copy[1] = linear(j, s_copy[1]);
        s_copy[2] = linear(j, s_copy[2]);
        s_copy[3] = linear(j, s_copy[3]);
        
        sbox_inverse(&s_copy[0], &s_copy[1], &s_copy[2], &s_copy[3]);
        
        s_copy[0] ^= round_keys[i][0];
        s_copy[1] ^= round_keys[i][1];
        s_copy[2] ^= round_keys[i][2];
        s_copy[3] ^= round_keys[i][3];
    }
    
    // Faulty round
    //print_hex(s_copy,4);
    s_copy[reg] ^= (0x80000000 >> k);
    //print_hex(s_copy,4);
    
    // Round 1
    s_copy[0] = linear(1, s_copy[0]);
    s_copy[1] = linear(1, s_copy[1]);
    s_copy[2] = linear(1, s_copy[2]);
    s_copy[3] = linear(1, s_copy[3]);
    
    sbox_inverse(&s_copy[0], &s_copy[1], &s_copy[2], &s_copy[3]);
    
    s_copy[0] ^= round_keys[1][0];
    s_copy[1] ^= round_keys[1][1];
    s_copy[2] ^= round_keys[1][2];
    s_copy[3] ^= round_keys[1][3];
    
    // Round 0
    s_copy[0] = linear(0, s_copy[0]);
    s_copy[1] = linear(0, s_copy[1]);
    s_copy[2] = linear(0, s_copy[2]);
    s_copy[3] = linear(0, s_copy[3]);
    
    sbox_inverse(&s_copy[0], &s_copy[1], &s_copy[2], &s_copy[3]);
    
    s_copy[0] ^= round_keys[0][0];
    s_copy[1] ^= round_keys[0][1];
    s_copy[2] ^= round_keys[0][2];
    s_copy[3] ^= round_keys[0][3];
    
    // Generate plaintext
    out[0] = s_copy[0];
    out[1] = s_copy[1];
    out[2] = s_copy[2];
    out[3] = s_copy[3];
}

// Online phase (Table O)

void online_phase1(uint32_t ciphertext[4], uint32_t key[8], uint32_t result[4], uint8_t O[4][32][4], uint32_t subkey[4]) {
    uint32_t faulty_plaintext[4];
    
    for(int reg = 0; reg < 4; reg += 3){
        for(int k = 0; k < 16; k++){
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
              delta_p[i] = result[i] ^ state1[i];
            }
            //print_hex(delta_ciphertext, 4);
            
            O[reg][k][0] = (delta_p[0] >> (32-(k+1))) & 1;
            O[reg][k][1] = (delta_p[1] >> (32-(k+1))) & 1;
            O[reg][k][2] = (delta_p[2] >> (32-(k+1))) & 1;
            O[reg][k][3] = (delta_p[3] >> (32-(k+1))) & 1;
            
            O[reg][16+(7+k)%16][0] = (delta_p[0] >> (32-(16+(7+k)%16+1))) & 1;
            O[reg][16+(7+k)%16][1] = (delta_p[1] >> (32-(16+(7+k)%16+1))) & 1;
            O[reg][16+(7+k)%16][2] = (delta_p[2] >> (32-(16+(7+k)%16+1))) & 1;
            O[reg][16+(7+k)%16][3] = (delta_p[3] >> (32-(16+(7+k)%16+1))) & 1;
            
            //printf("%d %d\n", G[3][k][0], G[3][k][1] );
        }
    }
    
    for(int i = 0; i < 32; i++){
        O[2][i][2] = 1;       
        O[2][i][3] = O[3][i][0];                    
        
        O[1][i][2] = O[0][i][2];       
        O[1][i][3] = (O[0][i][2] & (O[3][i][0] ^ O[3][i][2])) ^ O[0][i][1];                             
    }
    
}

