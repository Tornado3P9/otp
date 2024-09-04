use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use clap::{Arg, ArgGroup, Command};
use rand::Rng;

fn main() -> io::Result<()> {
    let matches = Command::new("otp")
        .version("1.0")
        .author("Tornado3P9")
        .about("Encrypts or decrypts a file using One-Time-Pad (OTP)")
        .arg(Arg::new("encrypt")
            .short('e')
            .long("encrypt")
            .help("Encrypt the data file")
            .num_args(1))
        .arg(Arg::new("decrypt")
            .short('d')
            .long("decrypt")
            .help("Decrypt the cipher file")
            .num_args(1))
        .group(ArgGroup::new("mode")
            .args(&["encrypt", "decrypt"])
            .required(true))
        .get_matches();

    let is_encrypt: bool = matches.contains_id("encrypt");
    let is_decrypt: bool = matches.contains_id("decrypt");
    if is_encrypt {
        let data_file_path = PathBuf::from(matches.get_one::<String>("encrypt").unwrap());
        let mut data_file = File::open(&data_file_path)?;
        let mut data_buffer = Vec::new();
        data_file.read_to_end(&mut data_buffer)?;

        let key = generate_random_key(data_buffer.len());
        let ciphertext = xor_operation(&data_buffer, &key)?;

        let mut cipher_file = File::create("cipher.txt")?;
        cipher_file.write_all(&ciphertext)?;

        let mut key_file = File::create("key.txt")?;
        key_file.write_all(&key)?;
    } else if is_decrypt {
        let mut cipher_file = File::open("cipher.txt")?;
        let mut ciphertext = Vec::new();
        cipher_file.read_to_end(&mut ciphertext)?;

        let mut key_file = File::open("key.txt")?;
        let mut key = Vec::new();
        key_file.read_to_end(&mut key)?;

        let plaintext = xor_operation(&ciphertext, &key)?;

        let output_file_path = PathBuf::from(matches.get_one::<String>("decrypt").unwrap());
        
        let mut decrypted_file = File::create(output_file_path)?;
        decrypted_file.write_all(&plaintext)?;
    } else {
        eprintln!("You must specify either --encrypt or --decrypt.");
        std::process::exit(1);
    }

    Ok(())
}

fn generate_random_key(length: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..length).map(|_| rng.gen()).collect()
}

fn xor_operation(text: &[u8], key: &[u8]) -> io::Result<Vec<u8>> {
    if text.len() != key.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Key must be the same length as the text."));
    }
    Ok(text.iter().zip(key.iter()).map(|(&t, &k)| t ^ k).collect())
}
