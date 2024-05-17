extern crate crypto;
use crypto::aes::{self, KeySize};
use crypto::blockmodes::NoPadding;
use crypto::buffer::{BufferResult, ReadBuffer, WriteBuffer};
use crypto::buffer::RefReadBuffer;
use crypto::buffer::RefWriteBuffer;
use crypto::symmetriccipher::Encryptor;
use crypto::symmetriccipher::Decryptor;

// Function to encrypt plaintext using AES encryption
fn encrypt(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    let mut encryptor = aes::cbc_encryptor(
        KeySize::KeySize256,
        key,
        &[0u8; 16], // Initialization vector (IV)
        NoPadding,
    );

    let mut ciphertext = vec![0; plaintext.len() + 16]; // Output buffer
    let mut read_buffer = RefReadBuffer::new(plaintext);
    let mut write_buffer = RefWriteBuffer::new(&mut ciphertext);

    // Encrypt the plaintext
    encryptor.encrypt(&mut read_buffer, &mut write_buffer, true).unwrap();

    // Get the actual size of the ciphertext
    let result = write_buffer.take_read_buffer();
    let ciphertext_len = match result {
        BufferResult::BufferUnderflow => write_buffer.position(),
        BufferResult::BufferOverflow => panic!("Buffer overflow occurred"),
    };

    // Truncate the ciphertext to its actual length
    ciphertext.truncate(ciphertext_len);

    ciphertext
}

// Function to decrypt ciphertext using AES decryption
fn decrypt(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    let mut decryptor = aes::cbc_decryptor(
        KeySize::KeySize256,
        key,
        &[0u8; 16], // Initialization vector (IV)
        NoPadding,
    );

    let mut plaintext = vec![0; ciphertext.len()];
    let mut read_buffer = RefReadBuffer::new(ciphertext);
    let mut write_buffer = RefWriteBuffer::new(&mut plaintext);

    // Decrypt the ciphertext
    decryptor.decrypt(&mut read_buffer, &mut write_buffer, true).unwrap();

    // Get the actual size of the plaintext
    let result = write_buffer.take_read_buffer();
    let plaintext_len = match result {
        BufferResult::BufferUnderflow => write_buffer.position(),
        BufferResult::BufferOverflow => panic!("Buffer overflow occurred"),
    };

    // Truncate the plaintext to its actual length
    plaintext.truncate(plaintext_len);

    plaintext
}

fn main() {
    let key = b"supersecretkey"; // 16, 24, or 32 bytes key for AES-128, AES-192, or AES-256 respectively
    let plaintext = b"Hello, world!"; // Message to be encrypted

    // Encrypt the plaintext
    let ciphertext = encrypt(plaintext, key);

    println!("Ciphertext: {:?}", ciphertext);

    // Decrypt the ciphertext
    let decrypted = decrypt(&ciphertext, key);

    // Convert the decrypted bytes to a UTF-8 string
    let decrypted_str = String::from_utf8(decrypted).unwrap();

    println!("Decrypted: {}", decrypted_str);
}
