// Logging
// use log::{info, error};

use std::fs::{self, File};
use std::io::{self, Read, Write};

// read user input
use rpassword::read_password;

// Encode Base64
use base64::Engine;
use base64::prelude::BASE64_STANDARD;

// Commandline Arguments Parser
use clap::{Parser, Subcommand};

// OsRng
use rand::rand_core;
use rand_core::{OsRng, TryRngCore};

// chacha20
use rand::RngCore;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

// Argon2
use argon2::Argon2;

// #[derive(Parser, Debug)]
// #[command(name = "otp", version = "0.2.0", author = "Tornado3P9", about = "Generates keys from passwords using different algorithms and encrypts/decrypts a file using XOR bit operation")]
// struct Cli {
//     #[arg(short, long, value_name = "ALGORITHM", help = "Algorithm to use for key generation")]
//     algorithm: Algorithm,

//     // #[arg(short, long, help = "Password")]
//     // password: String,

//     // #[arg(short, long, help = "Length of the key")]
//     // length: usize,
// }

#[derive(Parser, Debug)]
#[command(version, about = "Generates keys from passwords using different algorithms and encrypts/decrypts a file using XOR bit operation")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Encrypt a file
    Encrypt {
        #[arg(short, long, value_name = "ALGORITHM", help = "Algorithm to use for key generation")]
        algorithm: Algorithm,
    },
    /// Decrypt a file
    Decrypt {
        #[arg(short, long, value_name = "ALGORITHM", help = "Algorithm to use for key generation")]
        algorithm: Algorithm,
    },
}

#[derive(Debug, Clone, PartialEq)]
enum Algorithm {
    Simple,
    ChaCha20,
    Argon2,
    // Add more algorithms here
}

impl std::str::FromStr for Algorithm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "simple" => Ok(Algorithm::Simple),
            "chacha20" => Ok(Algorithm::ChaCha20),
            "argon2" => Ok(Algorithm::Argon2),
            // Add more algorithms here
            _ => Err(format!("Unknown algorithm: {}", s)),
        }
    }
}

fn main() {
    // TODO: implement logging instead of println
    // env_logger::init();
    // info!("Done something.");
    let args = Cli::parse();

    match args.command {
        Commands::Encrypt { algorithm } => {
            let raw_data = read_file_to_vec("example.txt");
            if raw_data.is_empty() {
                eprintln!("No data to process. Exiting.");
                std::process::exit(1);
            }
            println!("raw_data: {:?}", raw_data);

            let passphrase = match get_user_input(true) {
                Ok(passphrase) => passphrase,
                Err(e) => {
                    eprintln!("Error getting user input: {}", e);
                    std::process::exit(1);
                }
            };
            println!("passphrase: {:?}", passphrase);

            let salt_length: usize = 16; // min 16 Bytes, but <= 255 or it will require more than one Byte for pushing to the 'ciphertext' vector
            let salt: Vec<u8> = generate_random_sequence(salt_length);

            let key: Vec<u8> = match algorithm {
                Algorithm::Simple => simple_algorithm(&passphrase, raw_data.len()),
                Algorithm::ChaCha20 => chacha20_algorithm(&passphrase, raw_data.len()),
                Algorithm::Argon2 => argon2_algorithm(&passphrase, &salt, raw_data.len()),
                // Add more algorithms here
            };
            println!("Generated key: {:?}", key);

            let mut ciphertext: Vec<u8> = xor_operation(&raw_data, &key);
            println!("Ciphertext: {:?}", ciphertext);

            if algorithm == Algorithm::Argon2 {
                ciphertext.extend(salt); // Adding the salt to the ciphertext for writing them to a file together in a later step
                ciphertext.push(salt_length as u8); // Cast the usize to u8 and push it to the end of the vector
            }

            write_base64_to_file("cipher.txt", &ciphertext);
        }
        Commands::Decrypt { algorithm } => {
            let encrypted_data = read_base64_from_file("cipher.txt");
            if encrypted_data.is_empty() {
                eprintln!("No data to process. Exiting.");
                std::process::exit(1);
            }

            let passphrase = match get_user_input(false) {
                Ok(passphrase) => passphrase,
                Err(e) => {
                    eprintln!("Error getting user input: {}", e);
                    std::process::exit(1);
                }
            };

            let mut encrypted_data_clone = encrypted_data.clone();

            let key: Vec<u8> = match algorithm {
                Algorithm::Simple => simple_algorithm(&passphrase, encrypted_data_clone.len()),
                Algorithm::ChaCha20 => chacha20_algorithm(&passphrase, encrypted_data_clone.len()),
                Algorithm::Argon2 => {
                    let salt_length = *encrypted_data_clone.last().unwrap() as usize;
                    let salt_start = encrypted_data_clone.len() - salt_length - 1;
                    let salt = &encrypted_data[salt_start..salt_start + salt_length];
                    encrypted_data_clone = encrypted_data[..salt_start].to_vec();
                    argon2_algorithm(&passphrase, salt, salt_start)
                }
                // Add more algorithms here
            };
            let decrypted_data = xor_operation(&encrypted_data_clone, &key);

            println!("Decrypted data: {:?}", decrypted_data);
            write_vec_to_file("decrypted.txt", &decrypted_data);
        }
    }

}

// fn generate_key(algorithm: &Algorithm, password: &str, key_length: usize, salt: &[u8]) -> Vec<u8> {
//     match algorithm {
//         Algorithm::Simple => simple_algorithm(password, key_length),
//         Algorithm::ChaCha20 => chacha20_algorithm(password, key_length),
//         Algorithm::Argon2 => argon2_algorithm(password, salt, key_length),
//         // Add more algorithms here
//     }
// }

fn generate_random_sequence(length: usize) -> Vec<u8> {
    let mut key: Vec<u8> = vec![0u8; length];
    OsRng.try_fill_bytes(&mut key).unwrap();
    key
}

fn simple_algorithm(password: &str, key_length: usize) -> Vec<u8> {
    password.bytes().cycle().take(key_length).collect()
}

fn chacha20_algorithm(password: &str, key_length: usize) -> Vec<u8> {
    // Create a seed from the input string using a cryptographic hash function
    let mut hasher = Sha256::new();
    hasher.update(password);
    let hash_result = hasher.finalize();

    // Convert the hash result to an array of bytes
    let seed_bytes: [u8; 32] = hash_result.into();

    // Create a ChaCha RNG with the seed
    let mut rng = ChaCha20Rng::from_seed(seed_bytes);

    // Fill a Vec<u8> with random bytes
    let mut key = vec![0u8; key_length];
    rng.fill_bytes(&mut key);

    key
}

fn argon2_algorithm(password: &str, salt: &[u8], key_length: usize) -> Vec<u8> {
    let mut key = vec![0u8; key_length];
    if let Err(e) = Argon2::default().hash_password_into(password.as_bytes(), salt, &mut key) {
        eprintln!("An error occurred with argon2: {}", e);
        std::process::exit(1);
    }
    key
}

fn xor_operation(text: &[u8], key: &[u8]) -> Vec<u8> {
    if text.len() != key.len() {
        panic!("Key must be the same length as the text.");
    }
    text.iter().zip(key.iter()).map(|(&t, &k)| t ^ k).collect()
}

fn get_user_input(confirm: bool) -> Result<String, String> {
    loop {
        print!("Please enter a passphrase: ");
        if let Err(e) = io::stdout().flush() {
            return Err(format!("Failed to flush stdout: {}", e));
        }

        let user_input = match read_password() {
            Ok(input) => input,
            Err(e) => return Err(format!("Failed to read password: {}", e)),
        };

        if confirm {
            if user_input.len() < 12 {
                println!(
                    "\nInput too short. Your passphrase must be at least 12 characters long. Please ensure it includes a mix of letters, numbers, and special characters to enhance security."
                );
                continue;
            }

            print!("Please re-enter your passphrase for confirmation: ");
            if let Err(e) = io::stdout().flush() {
                return Err(format!("Failed to flush stdout: {}", e));
            }

            let confirm_input = match read_password() {
                Ok(input) => input,
                Err(e) => return Err(format!("Failed to read password: {}", e)),
            };

            if user_input == confirm_input {
                return Ok(user_input);
            } else {
                println!("\nPassphrases do not match. Please try again.");
            }
        } else {
            return Ok(user_input);
        }
    }
}

// fn read_file_to_vec(file_path: &str) -> Result<Vec<u8>, io::Error> {
//     let mut file = File::open(file_path)?;
//     let mut buffer = Vec::new();
//     file.read_to_end(&mut buffer)?;
//     Ok(buffer)
// }
fn read_file_to_vec(file_path: &str) -> Vec<u8> {
    let mut file = match File::open(file_path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Failed to open file: {}", e);
            return Vec::new();
        }
    };

    let mut buffer = Vec::new();
    if let Err(e) = file.read_to_end(&mut buffer) {
        eprintln!("Failed to read file: {}", e);
        return Vec::new();
    }

    // if buffer.is_empty() {
    //     eprintln!("File is empty.");
    // }

    buffer
}

fn write_base64_to_file(file_path: &str, data: &[u8]) {
    let base64_data = BASE64_STANDARD.encode(data);

    match File::create(file_path) {
        Ok(mut file) => {
            if let Err(e) = file.write_all(base64_data.as_bytes()) {
                eprintln!("Failed to write to file: {}", e);
            }
        }
        Err(e) => {
            eprintln!("Failed to create file: {}", e);
        }
    }
}

fn read_base64_from_file(file_path: &str) -> Vec<u8> {
    match fs::read_to_string(file_path) {
        Ok(base64_data) => match BASE64_STANDARD.decode(&base64_data) {
            Ok(decoded_data) => decoded_data,
            Err(e) => {
                eprintln!("Decoding error: {}", e);
                Vec::new() // Return an empty vector
            }
        },
        Err(e) => {
            eprintln!("File read error: {}", e);
            Vec::new() // Return an empty vector
        }
    }
}

fn write_vec_to_file(file_path: &str, data: &[u8]) {
    match File::create(file_path) {
        Ok(mut file) => {
            if let Err(e) = file.write_all(data) {
                eprintln!("Failed to write data to file: {}", e);
            }
        }
        Err(e) => {
            eprintln!("Failed to create file: {}", e);
        }
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_key_length() {
        let key_length: usize = 16;
        let key: Vec<u8> = generate_random_sequence(key_length);
        assert_eq!(key_length, key.len());
    }

    #[test]
    fn test_random_key_uniqueness() {
        let length = 10;
        let key1 = generate_random_sequence(length);
        let key2 = generate_random_sequence(length);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_chacha20_algorithm() {
        let key_1: Vec<u8> = chacha20_algorithm("private", 42);
        let key_2: Vec<u8> = chacha20_algorithm("private", 42);
        let key_3: Vec<u8> = chacha20_algorithm("secret", 42);
        assert_eq!(key_1, key_2);
        assert_ne!(key_1, key_3);
        assert_eq!(key_1.len(), 42);
    }

    #[test]
    fn test_argon2_algorithm() {
        let passphrase: String = "private".to_string();
        let salt_length: usize = 16;
        let salt_1: Vec<u8> = generate_random_sequence(salt_length);
        let salt_2: Vec<u8> = generate_random_sequence(salt_length);
        let key_length: usize = 42;
        let key_1: Vec<u8> = argon2_algorithm(&passphrase, &salt_1, key_length);
        let key_2: Vec<u8> = argon2_algorithm(&passphrase, &salt_2, key_length);
        let key_3: Vec<u8> = argon2_algorithm(&passphrase, &salt_1, key_length);
        assert_ne!(key_1, key_2);
        assert_eq!(key_1, key_3);
        assert_eq!(key_1.len(), key_length);
    }
}
