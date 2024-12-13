# One-Time-Pad Generator (OTP)

Just a fun project that encrypts or decrypts a file using One-Time-Pad (Vigenère cipher with a key that has the same length as the data that it encrypts and using the XOR bit operator instead of plaintext modulo calculation)

```
Usage: otp -e secret.txt
       otp -d decrypted.txt

Options:
  -e, --encrypt <encrypt>            Encrypt the file data (plain otp)
      --ewp-chacha20 <ewp-chacha20>  Encrypt .. with a passphrase
      --ewp-argon2 <ewp-argon2>      Encrypt .. with a passphrase
      --ewp-aes256 <ewp-aes256>      Encrypt .. with a passphrase and AES-256-CBC (openssl)
  -d, --decrypt <decrypt>            Decrypt the cipher file (plain otp)
      --dwp-chacha20 <dwp-chacha20>  Decrypt .. with a passphrase
      --dwp-argon2 <dwp-argon2>      Decrypt .. with a passphrase
      --dwp-aes256 <dwp-aes256>      Decrypt .. with a passphrase and AES-256-CBC (openssl)
  -h, --help                         Print help
  -V, --version                      Print version
```

Dependencies for Ubuntu:  
```bash
sudo apt install libssl-dev
```

### Further Readings:

- [Practical Cryptography for Developers - eBook](https://cryptobook.nakov.com/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/index.html)
- [Public Key Encryption - cs.stanford.edu](https://cs.stanford.edu/people/eroberts/courses/cs181/projects/public-key-encryption/ee.html)
- [Elliptic Curve Points - Desmos](https://www.desmos.com/calculator/ialhd71we3)
- [Bash Script for using AES256 via openssl](https://github.com/ChrisTitusTech/linutil/blob/79eb7525529c405cf4cd05ee28a5aba520e81f53/core/tabs/utils/encrypt_decrypt_tool.sh)
- [https://github.com/RustCrypto](https://github.com/RustCrypto)
- [Geheime Botschaften. Die Kunst der Verschlüsselung von der Antike bis in die Zeiten des Internet - Simon Singh](https://www.amazon.de/Geheime-Botschaften-Verschl%C3%BCsselung-Antike-Internet/dp/3423330716/)
