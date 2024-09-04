# One-Time-Pad Generator (OTP)

Just a fun project that encrypts or decrypts a file using One-Time-Pad (Vigenère cipher with a key that has the same length as the data that it encrypts and using the XOR bit operator instead of plaintext modulo calculation)

```bash
Usage: otp -e secret.txt
       otp -d decrypted.txt

Options:
  -e, --encrypt <encrypt>  Encrypt the data file
  -d, --decrypt <decrypt>  Decrypt the cipher file
  -h, --help               Print help
  -V, --version            Print version
```
