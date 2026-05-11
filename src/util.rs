use crate::lookup::{S_BOX, S_BOX_INVERSE};
use std::cmp::min;

pub type Word = [u8; 4];
pub type State = [[u8; 4]; 4];

// ================ GF(2^8) Arithmetic ================

pub const fn xtime(x: u8) -> u8 {
    (x << 1) ^ if x & 0x80 != 0 { 0x1B } else { 0 }
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0;

    while b != 0 {
        if b & 1 != 0 {
            result ^= a;
        }

        let carry = a & 0x80;
        a <<= 1;
        if carry != 0 {
            a ^= 0x1B;
        }
        b >>= 1;
    }

    result
}

// ================ Word Operations ================

/// Performs a left rotation on a 4-byte word
pub fn rotl_word(word: &Word) -> Word {
    [word[1], word[2], word[3], word[0]]
}

/// Performs a right rotation on a 4-byte word
pub fn sub_word(word: &Word) -> Word {
    let mut result = [0u8; 4];
    for i in 0..4 {
        result[i] = S_BOX[word[i] as usize];
    }
    result
}

/// Performs a left rotation on a 4-byte word
pub fn xor_word(a: &Word, b: &Word) -> Word {
    [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]]
}

// ================ State Operations ================

/// Performs a shear on the state by rotating each row to the left by its row index
pub fn rotl_state(state: &mut State) {
    for (row, row_data) in state.iter_mut().enumerate().skip(1) {
        row_data.rotate_left(row);
    }
}

/// Performs a shear on the state by rotating each row to the right by its row index
pub fn rotr_state(state: &mut State) {
    for (row, row_data) in state.iter_mut().enumerate().skip(1) {
        row_data.rotate_right(row);
    }
}

/// Applies the S-box substitution to each byte in the state
pub fn sub_state(state: &mut State) {
    for row in 0..4 {
        for col in 0..4 {
            state[row][col] = S_BOX[state[row][col] as usize];
        }
    }
}

/// Applies the inverse S-box substitution to each byte in the state
pub fn sub_state_inv(state: &mut State) {
    for row in 0..4 {
        for col in 0..4 {
            state[row][col] = S_BOX_INVERSE[state[row][col] as usize];
        }
    }
}

/// XORs the state with the given round key
pub fn xor_state(state: &mut State, round_key: &[Word; 4]) {
    for row in 0..4 {
        for col in 0..4 {
            state[row][col] ^= round_key[col][row];
        }
    }
}

/// Mixes the columns of the state using the AES mix column transformation
pub fn mix_state(state: &mut State) {
    let mut temp = [0u8; 4];
    for col in 0..4 {
        temp[0] =
            gf_mul(2, state[0][col]) ^ gf_mul(3, state[1][col]) ^ state[2][col] ^ state[3][col];
        temp[1] =
            state[0][col] ^ gf_mul(2, state[1][col]) ^ gf_mul(3, state[2][col]) ^ state[3][col];
        temp[2] =
            state[0][col] ^ state[1][col] ^ gf_mul(2, state[2][col]) ^ gf_mul(3, state[3][col]);
        temp[3] =
            gf_mul(3, state[0][col]) ^ state[1][col] ^ state[2][col] ^ gf_mul(2, state[3][col]);

        for row in 0..4 {
            state[row][col] = temp[row];
        }
    }
}

/// Applies the inverse mix column transformation to the state
pub fn mix_state_inv(state: &mut State) {
    let mut temp = [0u8; 4];
    for col in 0..4 {
        temp[0] = gf_mul(0x0E, state[0][col])
            ^ gf_mul(0x0B, state[1][col])
            ^ gf_mul(0x0D, state[2][col])
            ^ gf_mul(0x09, state[3][col]);
        temp[1] = gf_mul(0x09, state[0][col])
            ^ gf_mul(0x0E, state[1][col])
            ^ gf_mul(0x0B, state[2][col])
            ^ gf_mul(0x0D, state[3][col]);
        temp[2] = gf_mul(0x0D, state[0][col])
            ^ gf_mul(0x09, state[1][col])
            ^ gf_mul(0x0E, state[2][col])
            ^ gf_mul(0x0B, state[3][col]);
        temp[3] = gf_mul(0x0B, state[0][col])
            ^ gf_mul(0x0D, state[1][col])
            ^ gf_mul(0x09, state[2][col])
            ^ gf_mul(0x0E, state[3][col]);

        for row in 0..4 {
            state[row][col] = temp[row];
        }
    }
}

/// Converts a 16-byte block into a 4x4 state matrix
/// Pads with zeros if the block is less than 16 bytes
/// Ignores extra bytes if the block is more than 16 bytes
pub fn to_state(block: &[u8]) -> State {
    let mut state = [[0u8; 4]; 4];
    let n = min(block.len(), 16);
    for i in 0..n {
        state[i % 4][i / 4] = block[i];
    }
    for i in n..16 {
        state[i % 4][i / 4] = 0;
    }
    state
}
