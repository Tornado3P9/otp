use argon2::Argon2;
use base64::prelude::*;
use clap::{Arg, ArgGroup, Command};
use rand::rngs::OsRng;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::PathBuf;

fn main() -> io::Result<()> {
    let matches = Command::new("otp")
        .version("1.4")
        .author("Tornado3P9")
        .about("Encrypts or decrypts a file using One-Time-Pad")
        .arg(
            Arg::new("encrypt")
                .short('e')
                .long("encrypt")
                .help("Encrypt the data file (plain otp)")
                .num_args(1),
        )
        .arg(
            Arg::new("ewp-chacha20")
                .long("ewp-chacha20")
                .help("Encrypt the data file with a passphrase")
                .num_args(1),
        )
        .arg(
            Arg::new("ewp-argon2")
                .long("ewp-argon2")
                .help("Encrypt the data file with a passphrase")
                .num_args(1),
        )
        .arg(
            Arg::new("decrypt")
                .short('d')
                .long("decrypt")
                .help("Decrypt the cipher file (plain otp)")
                .num_args(1),
        )
        .arg(
            Arg::new("dwp-chacha20")
                .long("dwp-chacha20")
                .help("Decrypt the cipher file with a passphrase")
                .num_args(1),
        )
        .arg(
            Arg::new("dwp-argon2")
                .long("dwp-argon2")
                .help("Decrypt the cipher file with a passphrase")
                .num_args(1),
        )
        .group(
            ArgGroup::new("mode")
                .args(&[
                    "encrypt",
                    "ewp-chacha20",
                    "ewp-argon2",
                    "decrypt",
                    "dwp-chacha20",
                    "dwp-argon2",
                ])
                .required(true),
        )
        .get_matches();

    if matches.contains_id("encrypt") {
        let data_file_path = PathBuf::from(matches.get_one::<String>("encrypt").unwrap());
        let mut data_file = File::open(&data_file_path)?;
        let mut data_buffer = Vec::new();
        data_file.read_to_end(&mut data_buffer)?;

        if data_buffer.is_empty() {
            return Err(data_buffer_empty_error_handler());
        }

        let key = generate_random_key(data_buffer.len());
        let ciphertext = xor_operation(&data_buffer, &key)?;

        let base64_cipher: String = BASE64_STANDARD.encode(&ciphertext);
        let base64_key: String = BASE64_STANDARD.encode(&key);
        let mut cipher_file = File::create("cipher.txt")?;
        cipher_file.write_all(base64_cipher.as_bytes())?;
        let mut key_file = File::create("key.txt")?;
        key_file.write_all(base64_key.as_bytes())?;
    } else if matches.contains_id("ewp-chacha20") {
        let data_file_path = PathBuf::from(matches.get_one::<String>("ewp-chacha20").unwrap());
        let mut data_file = File::open(&data_file_path)?;
        let mut data_buffer = Vec::new();
        data_file.read_to_end(&mut data_buffer)?;

        if data_buffer.is_empty() {
            return Err(data_buffer_empty_error_handler());
        }

        // let key = generate_random_key(data_buffer.len());
        let user_input = get_user_input();
        let key = generate_random_key_with_chacha20(&user_input, data_buffer.len());
        let ciphertext = xor_operation(&data_buffer, &key)?;

        // With base64-encoding:
        let base64_cipher: String = BASE64_STANDARD.encode(&ciphertext);
        let mut cipher_file = File::create("cipher.txt")?;
        cipher_file.write_all(base64_cipher.as_bytes())?;
    } else if matches.contains_id("ewp-argon2") {
        let data_file_path = PathBuf::from(matches.get_one::<String>("ewp-argon2").unwrap());
        let mut data_file: File = File::open(&data_file_path)?;
        let mut data_buffer: Vec<u8> = Vec::new();
        data_file.read_to_end(&mut data_buffer)?;

        if data_buffer.is_empty() {
            return Err(data_buffer_empty_error_handler());
        }

        let passphrase: String = get_user_input();

        let salt_length: usize = 16; // min 16 Bytes, but <= 255 or it will require more than one Byte for pushing to the 'ciphertext' vector
        let salt: Vec<u8> = generate_random_key(salt_length); // Generate a unique salt for this passphrase (also doesn't actually have to be CSPRNG)

        let key_length: usize = data_buffer.len();
        let key: Vec<u8> = handle_error(generate_random_key_with_argon2(
            passphrase.as_bytes(),
            &salt,
            key_length,
        ));
        let mut ciphertext: Vec<u8> = xor_operation(&data_buffer, &key)?;

        ciphertext.extend(salt); // Adding the salt to the ciphertext for writing them to a file together in a later step
        ciphertext.push(salt_length as u8); // Cast the usize to u8 and push it to the end of the vector

        let base64_cipher: String = BASE64_STANDARD.encode(&ciphertext);
        let mut cipher_file = File::create("cipher.txt")?;
        cipher_file.write_all(base64_cipher.as_bytes())?;
    } else if matches.contains_id("decrypt") {
        let base64_cipher: String = fs::read_to_string("cipher.txt")?;
        let binary_cipher: Vec<u8> = BASE64_STANDARD
            .decode(&base64_cipher)
            .expect("Failed to decode base64_cipher data");

        let base64_key: String = fs::read_to_string("key.txt")?;
        let binary_key: Vec<u8> = BASE64_STANDARD
            .decode(&base64_key)
            .expect("Failed to decode base64_key data");

        let plaintext = xor_operation(&binary_cipher, &binary_key)?;

        let output_file_path = PathBuf::from(matches.get_one::<String>("decrypt").unwrap());

        let mut decrypted_file = File::create(output_file_path)?;
        decrypted_file.write_all(&plaintext)?;
    } else if matches.contains_id("dwp-chacha20") {
        let base64_cipher: String = fs::read_to_string("cipher.txt")?;
        let binary_cipher: Vec<u8> = BASE64_STANDARD
            .decode(&base64_cipher)
            .expect("Failed to decode base64_cipher data");

        let user_input = get_user_input();
        let binary_key = generate_random_key_with_chacha20(&user_input, binary_cipher.len());

        let plaintext = xor_operation(&binary_cipher, &binary_key)?;

        let output_file_path = PathBuf::from(matches.get_one::<String>("dwp-chacha20").unwrap());

        let mut decrypted_file = File::create(output_file_path)?;
        decrypted_file.write_all(&plaintext)?;
    } else if matches.contains_id("dwp-argon2") {
        let base64_cipher: String = fs::read_to_string("cipher.txt")?;
        let binary_cipher_and_salt: Vec<u8> = BASE64_STANDARD
            .decode(&base64_cipher)
            .expect("Failed to decode base64_cipher data");

        let passphrase: String = get_user_input();
        let (cipher, salt) = extract_cipher_and_salt(&binary_cipher_and_salt).unwrap();
        let binary_key: Vec<u8> = handle_error(generate_random_key_with_argon2(
            passphrase.as_bytes(),
            &salt,
            cipher.len(),
        ));

        let plaintext = xor_operation(&cipher, &binary_key)?;

        let output_file_path = PathBuf::from(matches.get_one::<String>("dwp-argon2").unwrap());

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
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Key must be the same length as the text.",
        ));
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

        if input_trimmed.is_empty() {
            println!();
            continue;
        }

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

fn generate_random_key_with_chacha20(seed: &str, size: usize) -> Vec<u8> {
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

fn generate_random_key_with_argon2(
    passphrase: &[u8],
    salt: &[u8],
    key_length: usize,
) -> Result<Vec<u8>, argon2::password_hash::Error> {
    let mut key = vec![0u8; key_length];
    Argon2::default().hash_password_into(passphrase, salt, &mut key)?;
    Ok(key)
}

fn handle_error<T>(result: Result<T, argon2::password_hash::Error>) -> T {
    match result {
        Ok(value) => value,
        Err(e) => {
            eprintln!("An error occurred with argon2: {}", e);
            std::process::exit(1);
        }
    }
}

fn data_buffer_empty_error_handler() -> io::Error {
    // Define your custom error handling logic here
    io::Error::new(
        io::ErrorKind::Other,
        "The Vec<u8> data buffer from reading the source file is empty.",
    )
}

// fn extract_cipher_and_salt(mut vec: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
//     if let Some(&salt_length) = vec.last() {
//         let salt_start = vec.len() - salt_length as usize - 1;
//         let salt = vec.split_off(salt_start);
//         let cipher = vec;
//         // Remove the last byte which is the salt length
//         let salt = &salt[..salt.len() - 1];
//         (cipher, salt.to_vec())
//     } else {
//         // Handle the error case where the vector is empty
//         panic!("Data vector is empty, cannot extract cipher and salt");
//     }
// }

#[derive(Debug)]
enum ExtractError {
    EmptyVector,
    InvalidSaltLength,
}

fn extract_cipher_and_salt(vec: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ExtractError> {
    if vec.is_empty() {
        return Err(ExtractError::EmptyVector);
    }

    if vec.len() < 2 {
        return Err(ExtractError::InvalidSaltLength);
    }

    let salt_length = *vec.last().unwrap() as usize;
    if salt_length >= vec.len() - 5 || salt_length == 0 {
        // This checks if the salt length is greater than or equal to the length of the vector
        // minus 5 (which accounts for the minimum length of the cipher, that argon2 expects,
        // plus the salt length byte) or if the salt length is zero.
        return Err(ExtractError::InvalidSaltLength);
    }

    let salt_start: usize = vec.len() - salt_length - 1;
    let cipher: &[u8] = &vec[..salt_start];
    let salt: &[u8] = &vec[salt_start..vec.len() - 1];
    Ok((cipher.to_vec(), salt.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_vector() {
        let input = vec![];
        let result = extract_cipher_and_salt(&input);
        assert!(matches!(result, Err(ExtractError::EmptyVector)));
    }

    #[test]
    fn test_valid_cipher_and_salt() {
        let input: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 5]; // Cipher: [1, 2, 3, 4, 5, 6], Salt: [7, 8, 9, 10, 11], Salt length: 5
        let expected_cipher: Vec<u8> = vec![1, 2, 3, 4, 5, 6];
        let (cipher, _salt) = extract_cipher_and_salt(&input).unwrap();
        assert_eq!(cipher, expected_cipher);
    }

    #[test]
    fn test_salt_length_too_long() {
        let input = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 8]; // Salt length: 8, but actual data is only 3 bytes
        let result = extract_cipher_and_salt(&input);
        assert!(matches!(result, Err(ExtractError::InvalidSaltLength)));
    }

    #[test]
    fn test_salt_length_zero() {
        let input = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0]; // Salt length: 0
        let result = extract_cipher_and_salt(&input);
        assert!(matches!(result, Err(ExtractError::InvalidSaltLength)));
    }
}
