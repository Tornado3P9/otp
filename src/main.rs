use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use clap::{Arg, ArgGroup, Command};
use rand::rngs::OsRng;
use rand::{RngCore, SeedableRng};
use base64::prelude::*;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

fn main() -> io::Result<()> {
    let matches = Command::new("otp")
        .version("1.3")
        .author("Tornado3P9")
        .about("Encrypts or decrypts a file using One-Time-Pad")
        .arg(Arg::new("encrypt")
            .short('e')
            .long("encrypt")
            .help("Encrypt the data file")
            .num_args(1))
        .arg(Arg::new("ewp")
            .long("ewp")
            .help("Encrypt the data file with a passphrase")
            .num_args(1))
        .arg(Arg::new("decrypt")
            .short('d')
            .long("decrypt")
            .help("Decrypt the cipher file")
            .num_args(1))
        .arg(Arg::new("dwp")
            .long("dwp")
            .help("Decrypt the cipher file with a passphrase")
            .num_args(1))
        .group(ArgGroup::new("mode")
            .args(&["encrypt", "ewp", "decrypt", "dwp"])
            .required(true))
        .get_matches();

    let is_encrypt: bool = matches.contains_id("encrypt");
    let is_ewp: bool = matches.contains_id("ewp");
    let is_decrypt: bool = matches.contains_id("decrypt");
    let is_dwp: bool = matches.contains_id("dwp");
    if is_encrypt {
        let data_file_path = PathBuf::from(matches.get_one::<String>("encrypt").unwrap());
        let mut data_file = File::open(&data_file_path)?;
        let mut data_buffer = Vec::new();
        data_file.read_to_end(&mut data_buffer)?;

        let key = generate_random_key(data_buffer.len());
        let ciphertext = xor_operation(&data_buffer, &key)?;

        // // Just the binary data without base64-encoding:
        // let mut cipher_file = File::create("cipher.txt")?;
        // cipher_file.write_all(&ciphertext)?;
        // let mut key_file = File::create("key.txt")?;
        // key_file.write_all(&key)?;

        // With base64-encoding:
        let base64_cipher: String = BASE64_STANDARD.encode(&ciphertext);
        let base64_key: String = BASE64_STANDARD.encode(&key);
        let mut cipher_file = File::create("cipher.txt")?;
        cipher_file.write_all(base64_cipher.as_bytes())?;
        let mut key_file = File::create("key.txt")?;
        key_file.write_all(base64_key.as_bytes())?;

    } else if is_ewp {
        let data_file_path = PathBuf::from(matches.get_one::<String>("ewp").unwrap());
        let mut data_file = File::open(&data_file_path)?;
        let mut data_buffer = Vec::new();
        data_file.read_to_end(&mut data_buffer)?;

        // let key = generate_random_key(data_buffer.len());
        let user_input = get_user_input();
        let key = create_random_key_from_string(&user_input, data_buffer.len());
        let ciphertext = xor_operation(&data_buffer, &key)?;

        // With base64-encoding:
        let base64_cipher: String = BASE64_STANDARD.encode(&ciphertext);
        let mut cipher_file = File::create("cipher.txt")?;
        cipher_file.write_all(base64_cipher.as_bytes())?;

    } else if is_decrypt {
        let base64_cipher: String = fs::read_to_string("cipher.txt")?;
        let binary_cipher: Vec<u8> = BASE64_STANDARD.decode(&base64_cipher).expect("Failed to decode base64_cipher data");

        let base64_key: String = fs::read_to_string("key.txt")?;
        let binary_key: Vec<u8> = BASE64_STANDARD.decode(&base64_key).expect("Failed to decode base64_key data");

        let plaintext = xor_operation(&binary_cipher, &binary_key)?;

        let output_file_path = PathBuf::from(matches.get_one::<String>("decrypt").unwrap());
        
        let mut decrypted_file = File::create(output_file_path)?;
        decrypted_file.write_all(&plaintext)?;

    } else if is_dwp {
        let base64_cipher: String = fs::read_to_string("cipher.txt")?;
        let binary_cipher: Vec<u8> = BASE64_STANDARD.decode(&base64_cipher).expect("Failed to decode base64_cipher data");

        let user_input = get_user_input();
        let binary_key = create_random_key_from_string(&user_input, binary_cipher.len());

        let plaintext = xor_operation(&binary_cipher, &binary_key)?;

        let output_file_path = PathBuf::from(matches.get_one::<String>("dwp").unwrap());
        
        let mut decrypted_file = File::create(output_file_path)?;
        decrypted_file.write_all(&plaintext)?;

    } else {
        eprintln!("You must specify either --encrypt or --decrypt.");
        std::process::exit(1);
    }

    Ok(())
}

// // A pseudo-random number generator (PRNG)
// fn generate_random_key(length: usize) -> Vec<u8> {
//     let mut rng = rand::thread_rng();
//     (0..length).map(|_| rng.gen()).collect()
// }

// A cryptographically secure random number generator (CSPRNG)
fn generate_random_key(length: usize) -> Vec<u8> {
    let mut rng = OsRng;
    let mut key = vec![0u8; length];
    rng.fill_bytes(&mut key);
    key
}

fn xor_operation(text: &[u8], key: &[u8]) -> io::Result<Vec<u8>> {
    if text.len() != key.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Key must be the same length as the text."));
    }
    Ok(text.iter().zip(key.iter()).map(|(&t, &k)| t ^ k).collect())
}

fn get_user_input() -> String {
    let mut user_input = String::new();

    loop {
        print!("Please enter a passphrase: ");
        io::stdout().flush().unwrap();

        user_input.clear(); // Clear the previous user_input
        io::stdin()
            .read_line(&mut user_input)
            .expect("Failed to read line");

        // Trim the newline character and any leading/trailing whitespace
        let input_trimmed = user_input.trim();

        // Display the user input for verification
        println!("You entered: \"{}\"", input_trimmed);

        print!("Use this passphrase? [y]es / [n]o / [q]uit : ");
        io::stdout().flush().unwrap();

        let mut ask_to_continue = String::new();
        io::stdin()
            .read_line(&mut ask_to_continue)
            .expect("Failed to read line");

        let trimmed_ask_to_continue = ask_to_continue.trim(); // Trim whitespace and newline characters

        match trimmed_ask_to_continue {
            "y" | "" => break, // Accept 'yes' or Enter key (empty input)
            "q" => std::process::exit(0),
            _ => {
                // Loop back if 'no' or different input
                println!();
                continue;
            }
        }
    }

    user_input.trim().to_string()
}

fn create_random_key_from_string(seed: &str, size: usize) -> Vec<u8> {
    // Create a seed from the input string using a cryptographic hash function
    let mut hasher = Sha256::new();
    hasher.update(seed);
    let hash_result = hasher.finalize();

    // Convert the hash result to an array of bytes
    let seed_bytes: [u8; 32] = hash_result.into();

    // Create a ChaCha RNG with the seed
    let mut rng = ChaCha20Rng::from_seed(seed_bytes);

    // Fill a Vec<u8> with random bytes
    let mut key = vec![0u8; size];
    rng.fill_bytes(&mut key);

    key
}
