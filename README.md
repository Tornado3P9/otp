# OTP

Just a fun project that generates keys from passwords using different algorithms and encrypts/decrypts a file using XOR bit operation.

```
Usage: otp <COMMAND>

Commands:
  encrypt  Encrypt a file
  decrypt  Decrypt a file
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

Currently available algorithms are: **Simple, ChaCha20, Argon2,**

`otp encrypt --algorithm <ALGORITHM>`

### Further Readings:

- [Practical Cryptography for Developers - eBook](https://cryptobook.nakov.com/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/index.html)
- [Public Key Encryption - cs.stanford.edu](https://cs.stanford.edu/people/eroberts/courses/cs181/projects/public-key-encryption/ee.html)
- [Elliptic Curve Points - Desmos](https://www.desmos.com/calculator/ialhd71we3)
- [Bash Script for using AES256 via openssl](https://github.com/ChrisTitusTech/linutil/blob/79eb7525529c405cf4cd05ee28a5aba520e81f53/core/tabs/utils/encrypt_decrypt_tool.sh)
- [https://github.com/RustCrypto](https://github.com/RustCrypto)
- [Geheime Botschaften. Die Kunst der Verschlüsselung von der Antike bis in die Zeiten des Internet - Simon Singh](https://www.amazon.de/Geheime-Botschaften-Verschl%C3%BCsselung-Antike-Internet/dp/3423330716/)
