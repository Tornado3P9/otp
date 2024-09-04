# One-Time-Pad Generator (OTP)

Encrypts or decrypts a file using One-Time-Pad (Vigenère cipher with a key that has the same length as the data that it encrypts and using the XOR bit operator instead of plaintext modulo calculation)

```bash
USAGE:
    otp [FLAGS] <source_file>

FLAGS:
    -d, --decrypt    Decrypt the source file
    -e, --encrypt    Encrypt the source file
    -h, --help       Prints help information
    -V, --version    Prints version information

ARGS:
    <source_file>    The source file to process:
                     Either the plaintext file that
                     you want to encrypt or the new
                     filename for the decrypted data
```
