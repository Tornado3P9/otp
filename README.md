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

### Further Readings:

- [Practical Cryptography for Developers - eBook](https://cryptobook.nakov.com/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/index.html)
- [Public Key Encryption - cs.stanford.edu](https://cs.stanford.edu/people/eroberts/courses/cs181/projects/public-key-encryption/ee.html)
- [Elliptic Curve Points - Desmos](https://www.desmos.com/calculator/ialhd71we3)
- [Geheime Botschaften. Die Kunst der Verschlüsselung von der Antike bis in die Zeiten des Internet - Simon Singh](https://www.amazon.de/Geheime-Botschaften-Verschl%C3%BCsselung-Antike-Internet/dp/3423330716/)
