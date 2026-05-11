use crate::lookup::RCON;
use crate::util::{
    State, mix_state, mix_state_inv, rotl_word, rotl_state, rotr_state, sub_state, sub_state_inv,
    sub_word, to_state, xor_state, xor_word,
};

/// Turns a 16-byte key into 44 4-byte words (11 round keys)
/// 
/// # Arguments
/// * `key` - A 16-byte array representing the AES key
/// 
/// # Returns
/// A 44x4 array of bytes representing the expanded key schedule
fn expand_key(key: &[u8; 16]) -> [[u8; 4]; 44] {
    let mut words = [[0u8; 4]; 44];

    for i in 0..4 {
        words[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
    }

    for i in 4..44 {
        let mut temp = words[i - 1];
        if i % 4 == 0 {
            temp = sub_word(&rotl_word(&temp));
            temp[0] ^= RCON[i / 4 - 1];
        }
        words[i] = xor_word(&words[i - 4], &temp);
    }

    words
}

/// Performs one round of AES encryption on the state
fn round(state: &mut State, round_key: &State, mix_column: bool) {
    sub_state(state);
    rotl_state(state);
    if mix_column {
        mix_state(state);
    }
    xor_state(state, round_key);
}

/// Performs one round of AES decryption on the state
fn round_inv(state: &mut State, round_key: &State, mix_column: bool) {
    xor_state(state, round_key);
    if mix_column {
        mix_state_inv(state);
    }
    rotr_state(state);
    sub_state_inv(state);
}

/// Generates a random 16-byte AES key
pub fn generate_key() -> [u8; 16] {
    rand::random()
}

/// Encrypts the given plaintext with the provided key
/// 
/// # Arguments
/// * `plaintext` - A byte slice representing the plaintext to encrypt
/// * `key` - A 16-byte array representing the AES key
/// 
/// # Returns
/// A vector of bytes representing the encrypted ciphertext
pub fn encrypt(plaintext: &[u8], key: &[u8; 16]) -> Vec<u8> {
    let round_keys = expand_key(key);
    let mut ciphertext = Vec::new();

    for block in plaintext.chunks(16) {
        let mut state = to_state(block);

        xor_state(&mut state, &round_keys[0..4].try_into().unwrap());

        for i in 1..10 {
            round(
                &mut state,
                &round_keys[4 * i..4 * (i + 1)].try_into().unwrap(),
                true,
            );
        }

        round(&mut state, &round_keys[40..44].try_into().unwrap(), false);

        for i in 0..4 {
            for j in 0..4 {
                ciphertext.push(state[j][i]);
            }
        }
    }

    ciphertext
}

/// Decrypts the given ciphertext with the provided key
/// 
/// # Arguments
/// * `ciphertext` - A byte slice representing the ciphertext to decrypt
/// * `key` - A 16-byte array representing the AES key
/// 
/// # Returns
/// A vector of bytes representing the decrypted plaintext
pub fn decrypt(ciphertext: &[u8], key: &[u8; 16]) -> Vec<u8> {
    let round_keys = expand_key(key);
    let mut plaintext = Vec::new();

    for block in ciphertext.chunks(16) {
        let mut state = to_state(block);

        round_inv(&mut state, &round_keys[40..44].try_into().unwrap(), false);

        for i in (1..10).rev() {
            round_inv(
                &mut state,
                &round_keys[4 * i..4 * (i + 1)].try_into().unwrap(),
                true,
            );
        }

        xor_state(&mut state, &round_keys[0..4].try_into().unwrap());

        for i in 0..4 {
            for j in 0..4 {
                plaintext.push(state[j][i]);
            }
        }
    }

    plaintext
}
