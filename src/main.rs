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
// use aes_gcm::{
//     aead::{AeadCore, AeadInPlace, KeyInit},
//     Aes256Gcm,
// };
use openssl::symm::{Cipher, Crypter, Mode};
use openssl::rand::rand_bytes;

fn main() -> io::Result<()> {
    let matches = Command::new("otp")
        .version("1.5")
        .author("Tornado3P9")
        .about("Encrypts or decrypts a file using One-Time-Pad")
        .override_usage("otp -e INPUT_FILE\n       otp -d OUTPUT_FILE",)
        .arg(Arg::new("encrypt").short('e').long("encrypt").help("Encrypt the file data (plain otp)").num_args(1),)
        .arg(Arg::new("ewp-chacha20").long("ewp-chacha20").help("Encrypt .. with a passphrase").num_args(1),)
        .arg(Arg::new("ewp-argon2").long("ewp-argon2").help("Encrypt .. with a passphrase").num_args(1),)
        .arg(Arg::new("ewp-aes256").long("ewp-aes256").help("Encrypt .. with a passphrase and AES-256-CBC (openssl)").num_args(1),)
        .arg(Arg::new("decrypt").short('d').long("decrypt").help("Decrypt the cipher file (plain otp)").num_args(1),)
        .arg(Arg::new("dwp-chacha20").long("dwp-chacha20").help("Decrypt .. with a passphrase").num_args(1),)
        .arg(Arg::new("dwp-argon2").long("dwp-argon2").help("Decrypt .. with a passphrase").num_args(1),)
        .arg(Arg::new("dwp-aes256").long("dwp-aes256").help("Decrypt .. with a passphrase and AES-256-CBC (openssl)").num_args(1),)
        .group(ArgGroup::new("mode")
            .args(&["encrypt","ewp-chacha20","ewp-argon2","ewp-aes256","decrypt","dwp-chacha20","dwp-argon2","dwp-aes256",])
            .required(true),
        )
        .get_matches();

    if matches.contains_id("encrypt") {
        let data_file_path: &String = matches.get_one::<String>("encrypt").unwrap();
        encrypt_otp(data_file_path)?;
    }
    else if matches.contains_id("ewp-chacha20") {
        let data_file_path: &String = matches.get_one::<String>("ewp-chacha20").unwrap();
        ewp_chacha20(data_file_path)?;
    }
    else if matches.contains_id("ewp-argon2") {
        let data_file_path: &String = matches.get_one::<String>("ewp-argon2").unwrap();
        ewp_argon2(data_file_path)?;
    }
    else if matches.contains_id("ewp-aes256") {
        let data_file_path: &String = matches.get_one::<String>("ewp-aes256").unwrap();
        ewp_aes256(data_file_path)?;
    }
    else if matches.contains_id("decrypt") {
        let data_file_path: &String = matches.get_one::<String>("decrypt").unwrap();
        decrypt_otp(data_file_path)?;
    }
    else if matches.contains_id("dwp-chacha20") {
        let data_file_path: &String = matches.get_one::<String>("dwp-chacha20").unwrap();
        dwp_chacha20(data_file_path)?;
    }
    else if matches.contains_id("dwp-argon2") {
        let data_file_path: &String = matches.get_one::<String>("dwp-argon2").unwrap();
        dwp_argon2(data_file_path)?;
    }
    else if matches.contains_id("dwp-aes256") {
        let data_file_path: &String = matches.get_one::<String>("dwp-aes256").unwrap();
        dwp_aes256(data_file_path)?;
    }
    else {
        eprintln!("You must specify either --encrypt or --decrypt.");
        // std::process::exit(1);
    }

    Ok(())
}


fn encrypt_otp(data_file_path: &str) -> io::Result<()> {
    let mut data_file = File::open(&data_file_path)?;
    let mut data_buffer: Vec<u8> = Vec::new();
    data_file.read_to_end(&mut data_buffer)?;

    if data_buffer.is_empty() {
        return Err(data_buffer_empty_error_handler());
    }

    let key: Vec<u8> = generate_random_key(data_buffer.len());
    let ciphertext: Vec<u8> = xor_operation(&data_buffer, &key)?;

    let base64_cipher: String = BASE64_STANDARD.encode(&ciphertext);
    let base64_key: String = BASE64_STANDARD.encode(&key);
    let mut cipher_file = File::create("cipher.txt")?;
    cipher_file.write_all(base64_cipher.as_bytes())?;
    let mut key_file = File::create("key.txt")?;
    key_file.write_all(base64_key.as_bytes())?;

    Ok(())
}

fn ewp_chacha20(data_file_path: &str) -> io::Result<()> {
    let mut data_file = File::open(&data_file_path)?;
    let mut data_buffer: Vec<u8> = Vec::new();
    data_file.read_to_end(&mut data_buffer)?;

    if data_buffer.is_empty() {
        return Err(data_buffer_empty_error_handler());
    }

    let user_input: String = get_user_input();
    let key: Vec<u8> = generate_random_key_with_chacha20(&user_input, data_buffer.len());
    let ciphertext: Vec<u8> = xor_operation(&data_buffer, &key)?;

    let base64_cipher: String = BASE64_STANDARD.encode(&ciphertext);
    let mut cipher_file = File::create("cipher.txt")?;
    cipher_file.write_all(base64_cipher.as_bytes())?;

    Ok(())
}

fn ewp_argon2(data_file_path: &str) -> io::Result<()> {
    let mut data_file = File::open(&data_file_path)?;
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
    // One could also consider creating or adding a hash of the data, or employing an alternative data verification method,
    // to determine if the data has been corrupted before encountering issues with the corrupted data itself.

    let base64_cipher: String = BASE64_STANDARD.encode(&ciphertext);
    let mut cipher_file = File::create("cipher.txt")?;
    cipher_file.write_all(base64_cipher.as_bytes())?;

    Ok(())
}

fn ewp_aes256(data_file_path: &str) -> io::Result<()> {
    let mut data_file = File::open(&data_file_path)?;
    let mut data_buffer: Vec<u8> = Vec::new();
    data_file.read_to_end(&mut data_buffer)?;

    if data_buffer.is_empty() {
        return Err(data_buffer_empty_error_handler());
    }

    let passphrase: String = get_user_input();

    let salt_length: usize = 16; // min 16 Bytes, but <= 255 or it will require more than one Byte for pushing to the 'ciphertext' vector
    let salt: Vec<u8> = generate_random_key(salt_length); // Generate a unique salt for this passphrase (also doesn't actually have to be CSPRNG)

    let cipher = Cipher::aes_256_cbc();
    let mut iv: Vec<u8> = vec![0; cipher.iv_len().unwrap()];
    rand_bytes(&mut iv).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let mut key: Vec<u8> = vec![0; cipher.key_len()];
    openssl::pkcs5::pbkdf2_hmac(passphrase.as_bytes(), &salt, 10000, openssl::hash::MessageDigest::sha256(), &mut key)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let mut crypter = Crypter::new(cipher, Mode::Encrypt, &key, Some(&iv))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let mut ciphertext: Vec<u8> = vec![0; data_buffer.len() + cipher.block_size()];
    let count: usize = crypter.update(&data_buffer, &mut ciphertext)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let rest: usize = crypter.finalize(&mut ciphertext[count..])
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    ciphertext.truncate(count + rest);

    // let mut encrypted_data = File::create("cipher.txt")?;
    // encrypted_data.write_all(&iv)?;
    // encrypted_data.write_all(&ciphertext)?;
    // encrypted_data.write_all(&salt)?;
    // encrypted_data.write_all(&salt_length)?;
    
    let mut encrypted_data: Vec<u8> = Vec::new();
    encrypted_data.extend(iv);
    encrypted_data.extend(ciphertext);
    encrypted_data.extend(salt);
    encrypted_data.push(salt_length as u8);

    let base64_cipher: String = BASE64_STANDARD.encode(&encrypted_data);
    let mut cipher_file = File::create("cipher.txt")?;
    cipher_file.write_all(base64_cipher.as_bytes())?;

    Ok(())
}

fn decrypt_otp(data_file_path: &str) -> io::Result<()> {    
    // let base64_cipher: String = fs::read_to_string("cipher.txt")?;
    // let base64_cipher: String = fs::read_to_string("cipher.txt")
    //     .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    // let base64_cipher: String = match fs::read_to_string("cipher.txt") {
    //     Ok(content) => content,
    //     Err(e) => return Err(io::Error::new(io::ErrorKind::Other, format!("Failed to read 'cipher.txt': {}", e))),
    // };
    let base64_cipher: String = fs::read_to_string("cipher.txt")
        .map_err(|e| {
            eprintln!("Failed to read 'cipher.txt'. Both 'cipher.txt' and 'key.txt' must be present.");
            e
        })?;
    let binary_cipher: Vec<u8> = BASE64_STANDARD
        .decode(&base64_cipher)
        .expect("Failed to decode base64_cipher data");

    let base64_key: String = fs::read_to_string("key.txt")
        .map_err(|e| {
            eprintln!("Failed to read 'key.txt'. Both 'cipher.txt' and 'key.txt' must be present.");
            e
        })?;
    let binary_key: Vec<u8> = BASE64_STANDARD
        .decode(&base64_key)
        .expect("Failed to decode base64_key data");

    let plaintext = xor_operation(&binary_cipher, &binary_key)?;

    let output_file_path = PathBuf::from(data_file_path);
    let mut decrypted_file = File::create(output_file_path)?;
    decrypted_file.write_all(&plaintext)?;

    Ok(())
}

fn dwp_chacha20(data_file_path: &str) -> io::Result<()> {
    let base64_cipher: String = fs::read_to_string("cipher.txt")
    .map_err(|e| {
        eprintln!("Failed to read 'cipher.txt'");
        e
    })?;
    let binary_cipher: Vec<u8> = BASE64_STANDARD
        .decode(&base64_cipher)
        .expect("Failed to decode base64_cipher data");

    let user_input = get_user_input();
    let binary_key = generate_random_key_with_chacha20(&user_input, binary_cipher.len());

    let plaintext = xor_operation(&binary_cipher, &binary_key)?;

    let output_file_path = PathBuf::from(data_file_path);
    let mut decrypted_file = File::create(output_file_path)?;
    decrypted_file.write_all(&plaintext)?;

    Ok(())
}

fn dwp_argon2(data_file_path: &str) -> io::Result<()> {
    let base64_cipher: String = fs::read_to_string("cipher.txt")
        .map_err(|e| {
            eprintln!("Failed to read 'cipher.txt'");
            e
        })?;
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

    let output_file_path = PathBuf::from(data_file_path);
    let mut decrypted_file = File::create(output_file_path)?;
    decrypted_file.write_all(&plaintext)?;

    Ok(())
}

fn dwp_aes256(data_file_path: &str) -> io::Result<()> {
    let base64_cipher: String = fs::read_to_string("cipher.txt")
        .map_err(|e| {
            eprintln!("Failed to read 'cipher.txt'");
            e
        })?;
    let iv_and_binary_cipher_and_salt: Vec<u8> = BASE64_STANDARD
        .decode(&base64_cipher)
        .expect("Failed to decode base64_cipher data");

    let passphrase: String = get_user_input();

    let cipher = Cipher::aes_256_cbc();
    // the blocks for AES will usually be 16 bytes in size (or 128 bits)..

    // Read the initialization vector (IV) from the beginning of the file
    let iv_len: usize = cipher.iv_len().unwrap();
    let mut iv: Vec<u8> = Vec::new();
    if iv_len > iv_and_binary_cipher_and_salt.len() {
        panic!("Initialization vector length is greater than the combined length of IV, cipher, and salt.");
    }
    for &item in iv_and_binary_cipher_and_salt.iter().take(iv_len) {
        iv.push(item);
    }

    let binary_cipher_and_salt_slice: &[u8] = iv_and_binary_cipher_and_salt.get(iv_len..).unwrap_or(&[]); // return cipher and salt or empty vector
    let (encrypted_data, salt) = extract_cipher_and_salt(&binary_cipher_and_salt_slice).unwrap();

    let mut key: Vec<u8> = vec![0; cipher.key_len()];
    openssl::pkcs5::pbkdf2_hmac(passphrase.as_bytes(), &salt, 10000, openssl::hash::MessageDigest::sha256(), &mut key)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("PBKDF2 operation failed: {}", e)))?;

    let mut crypter = Crypter::new(cipher, Mode::Decrypt, &key, Some(&iv))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let mut decrypted_data = vec![0; encrypted_data.len() + cipher.block_size()];
    let count = crypter.update(&encrypted_data, &mut decrypted_data)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let rest = crypter.finalize(&mut decrypted_data[count..])
        .map_err(|e| {
            if e.errors().iter().any(|error| error.reason() == Some("bad decrypt")) {
                io::Error::new(io::ErrorKind::InvalidInput, "Incorrect passphrase")
            } else {
                io::Error::new(io::ErrorKind::Other, format!("Finalize failed: {}", e))
            }
        })?;

    if count + rest > decrypted_data.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Decryption failed: output size exceeds buffer length"));
    }
    decrypted_data.truncate(count + rest);

    let mut output = File::create(data_file_path)?;
    output.write_all(&decrypted_data)?;

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

        if input_trimmed.is_empty() || input_trimmed.len() < 12 {
            println!("Input too short. Your passphrase must be at least 12 characters long. Please ensure it includes a mix of letters, numbers, and special characters to enhance security.");
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
    InvalidVectorLength,
}

fn extract_cipher_and_salt(vec: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ExtractError> {
    if vec.is_empty() {
        return Err(ExtractError::EmptyVector);
    }

    // Depends on line 'let salt_length: usize = 16;' where the number is hardcoded in the main function
    if vec.len() < 21 {
        // If the salt_length is at least 16, and the cipher is at least 4 because of the minimum length of the cipher that argon2 expects,
        // then together with the single salt_length_byte the min length of the vector has to be 16+4+1=21.
        // This means that I would begin with the check "vec.len()>=21 ?" because anything else would be incorrect anyway.
        // After this I could use Reed-Solomon error correction for the integrity of the actual data. But is it even necessary?
        // Still, when using an error correction crate, any other verification lines that follow will become redundant.
        return Err(ExtractError::InvalidVectorLength); // length of the whole cipher.txt data vector
    }

    let salt_length = *vec.last().unwrap() as usize;
    if salt_length > vec.len() - 5 || salt_length == 0 {
        // This checks if the salt length is greater than the length of the vector
        // minus 5 (which accounts for the minimum length of the cipher, that argon2 expects, plus the salt length byte)
        // or if the salt length is zero.
        return Err(ExtractError::InvalidSaltLength);
    }

    let salt_start: usize = vec.len() - salt_length - 1;
    let cipher: &[u8] = &vec[..salt_start];
    let salt: &[u8] = &vec[salt_start..vec.len() - 1];
    Ok((cipher.to_vec(), salt.to_vec()))
}

// use crc::{Crc, CRC_8_MAXIM_DOW};  // cargo add crc
// let data: Vec<u8> = vec![1, 2, 3, 4, 5]; // Your data here
// let checksum = crc8_checksum(&data);
// fn crc8_checksum(data: &[u8]) -> u8 {
//     let crc8 = Crc::<u8>::new(&CRC_8_MAXIM_DOW);
//     crc8.checksum(&data)
// }

// let digits: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
// let result = checkISBN(&digits);
// println!("The ISBN check result is: {}", result);
// fn checkISBN(digits: &[u8]) -> u8 {
//     let mut factor: u16 = 1;
//     let mut sum: u16 = 0;
//     for &digit in digits {
//         // sum += factor * (digit as u16); // sum could potentially experience value overflow for big numbers. However, in release mode, these checks are disabled, and overflow will result in wrapping.
//         sum = sum.wrapping_add(factor.wrapping_mul(digit as u16)); // because of sum being u16, wrapping basically performs modulo 65536 (because of 2**16)
//         factor += 1;
//     }
//     (sum % 256) as u8
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_key_length() {
        let key_length: usize = 16;
        let key: Vec<u8> = generate_random_key(key_length);
        assert_eq!(key_length, key.len());
    }

    #[test]
    fn test_empty_vector() {
        let input = vec![];
        let result = extract_cipher_and_salt(&input);
        assert!(matches!(result, Err(ExtractError::EmptyVector)));
    }

    #[test]
    fn test_valid_cipher_and_salt() {
        // Cipher: [1, 2, 3, 4], Salt: [5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20], Salt length: 16
        let input: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 16];
        let expected_cipher: Vec<u8> = vec![1, 2, 3, 4];
        let (cipher, _salt) = extract_cipher_and_salt(&input).unwrap();
        assert_eq!(cipher, expected_cipher);
    }

    #[test]
    fn test_salt_length_too_long() {
        let input = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 25]; // Salt length: 25, but actual data is only 21 bytes
        let result = extract_cipher_and_salt(&input);
        assert!(matches!(result, Err(ExtractError::InvalidSaltLength)));
    }

    #[test]
    fn test_data_length_too_short() {
        let input = vec![1, 2, 3, 4, 5, 2]; // Cipher: [1, 2, 3], Salt: [4, 5], Salt length: 2
        let result = extract_cipher_and_salt(&input);
        assert!(matches!(result, Err(ExtractError::InvalidVectorLength)));
    }

    #[test]
    fn test_salt_length_zero() {
        let input = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0]; // Salt length: 0
        let result = extract_cipher_and_salt(&input);
        assert!(matches!(result, Err(ExtractError::InvalidSaltLength)));
    }
}
