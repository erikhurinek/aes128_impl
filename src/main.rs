#![allow(dead_code, unused_variables)]

use std::fs;

mod aes_test;
mod lookup;
mod util;

fn main() {
    // Generate a random key
    let key = aes_test::generate_key();

    // Read plaintext from file
    let plaintext = fs::read("text/text00.txt").expect("Failed to read plaintext file");
    let length = plaintext.len();

    // Encrypt the plaintext
    let ciphertext = aes_test::encrypt(&plaintext, &key);

    // Display the ciphertext hex
    println!("Encrypted ciphertext: {}", hex::encode(&ciphertext));

    // Decrypt the ciphertext and trim to original length
    let mut decrypted_plaintext = aes_test::decrypt(&ciphertext, &key);
    decrypted_plaintext.truncate(length);

    // Display the decrypted plaintext
    println!(
        "Decrypted plaintext: {}",
        String::from_utf8(decrypted_plaintext).unwrap()
    );
}
