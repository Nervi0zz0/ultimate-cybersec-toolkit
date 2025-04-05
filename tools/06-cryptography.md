# 6. 🔒 Cryptography Tools

Cryptography underpins much of modern security, ensuring confidentiality (preventing unauthorized reading), integrity (detecting tampering), and authentication (verifying identity). Blue Teams utilize cryptographic tools for tasks like managing digital certificates, encrypting sensitive data, verifying file integrity, analyzing secure connections, and managing keys.

## Index of Tools in this Section

* [ccrypt](#ccrypt)
* [GnuPG (GPG)](#gnupg-gpg)
* [Hashing Utilities (Built-in OS Tools)](#hashing-utilities-built-in-os-tools)
* [OpenSSL](#openssl)

---

## ccrypt

* **Description:** A command-line utility for encrypting and decrypting files and streams, based on the Rijndael cipher (which was standardized as AES). It provides strong, password-based symmetric encryption for protecting individual files.
* **Key Features/Why it's useful:**
    * Simple, secure symmetric file encryption using AES.
    * Password-based encryption, easy to use for protecting sensitive files at rest.
    * Option to use keyfiles instead of passwords.
* **Official Website/Repository:** [http://ccrypt.sourceforge.net/](http://ccrypt.sourceforge.net/) (May also be available in Linux repositories)
* **Type:** CLI File Encryption Utility
* **Platform(s):** Linux, macOS, Windows (via ports or Cygwin/WSL).
* **Installation:**
    ```bash
    # Debian/Ubuntu
    sudo apt update && sudo apt install ccrypt
    # macOS (Homebrew)
    brew install ccrypt
    ```
* **Basic Usage Example:**
    ```bash
    # Encrypt a file (will prompt for password)
    ccrypt sensitive_file.txt 
    # (Creates sensitive_file.txt.cpt)

    # Decrypt a file (will prompt for password)
    ccrypt -d sensitive_file.txt.cpt 
    # (Recreates sensitive_file.txt)

    # Encrypt using a specific keyfile
    ccrypt -k mykeyfile sensitive_data
    ```
* **Alternatives:** GnuPG (more features, asymmetric option), OpenSSL (CLI, more complex for simple file encryption), VeraCrypt/LUKS (for disk encryption).
* **Notes/Tips:** Uses AES by default (usually 256-bit). Remember your password or keyfile, as there's no recovery otherwise. Good for quick encryption of specific files.

---

## GnuPG (GPG)

* **Description:** The GNU implementation of the OpenPGP standard, providing robust cryptographic privacy and authentication. It allows for encrypting and signing data and communications, featuring a versatile key management system. Commonly used for email encryption (like PGP) and file signing/encryption.
* **Key Features/Why it's useful:**
    * **Asymmetric Encryption:** Encrypting files/messages using a recipient's public key, ensuring only they can decrypt with their private key.
    * **Symmetric Encryption:** Encrypting files using a password (similar to ccrypt but integrated).
    * **Digital Signatures:** Signing files/messages to verify sender identity and ensure data integrity (non-repudiation).
    * **Key Management:** Generating, importing, exporting, and managing public/private key pairs.
    * **Web of Trust:** Verifying key authenticity through a decentralized trust model (or via keyservers).
* **Official Website/Repository:** [https://gnupg.org/](https://gnupg.org/)
* **Type:** CLI Encryption & Signing Tool (with GUI frontends available, e.g., Kleopatra, GPG Suite)
* **Platform(s):** Linux, macOS, Windows, BSD.
* **Installation:** Usually available via package managers. Installers available for Windows/macOS.
    ```bash
    # Debian/Ubuntu
    sudo apt update && sudo apt install gnupg
    # macOS (Homebrew)
    brew install gnupg
    ```
* **Basic Usage Example:**
    ```bash
    # Generate a new key pair (follow prompts)
    gpg --full-generate-key

    # List public keys in your keyring
    gpg --list-keys

    # Encrypt a file for a recipient using their public key
    gpg --encrypt --recipient [dirección de correo electrónico eliminada] document.txt
    # (Creates document.txt.gpg)

    # Decrypt a file encrypted for you
    gpg --decrypt document.txt.gpg > document.txt

    # Create a detached signature for a file
    gpg --detach-sign software.zip
    # (Creates software.zip.sig)

    # Verify a signature
    gpg --verify software.zip.sig software.zip 
    ```
* **Alternatives:** OpenSSL (can perform similar functions but less focused on PGP workflow), commercial PGP software.
* **Notes/Tips:** Securely managing your private key is paramount. Use strong passphrases. Understand concepts of public key infrastructure (PKI) or Web of Trust for key validation.

---

## Hashing Utilities (Built-in OS Tools)

* **Description:** Most operating systems include built-in command-line tools for calculating cryptographic hashes (like MD5, SHA-1, SHA-256) of files. Hashing produces a fixed-size "fingerprint" of data, primarily used by Blue Teams to verify file integrity (detect modifications) and sometimes used in storing password representations (though dedicated password hashing functions are better for that).
* **Key Features/Why it's useful:**
    * **Integrity Verification:** Comparing the hash of a downloaded file against a known-good hash provided by the source to ensure it wasn't corrupted or tampered with.
    * **Forensic Analysis:** Hashing evidence files to ensure they haven't been altered.
    * **Incident Response:** Identifying known malicious files by comparing their hashes against threat intelligence feeds.
* **Official Website/Repository:** N/A (Built into Operating Systems)
* **Type:** CLI Hashing Utilities
* **Platform(s):** Linux, macOS, Windows.
* **Installation:** Pre-installed on most systems. (Git Bash on Windows also provides Linux versions).
* **Basic Usage Example:**
    ```bash
    # Linux / macOS / Git Bash
    md5sum file.zip
    sha1sum file.zip
    sha256sum file.zip

    # Windows PowerShell
    Get-FileHash -Algorithm MD5 file.zip
    Get-FileHash -Algorithm SHA1 file.zip
    Get-FileHash -Algorithm SHA256 file.zip

    # Windows Command Prompt (cmd.exe)
    certutil -hashfile file.zip MD5
    certutil -hashfile file.zip SHA1
    certutil -hashfile file.zip SHA256
    ```
* **Alternatives:** OpenSSL (`openssl dgst -sha256 file.zip`), various third-party hashing tools (e.g., HashMyFiles GUI for Windows).
* **Notes/Tips:** MD5 and SHA-1 are considered cryptographically weak for collision resistance (avoid for signatures) but are still commonly used for basic file integrity checks or as IOCs. SHA-256 or stronger is recommended for new applications.

---

## OpenSSL

* **Description:** A robust, commercial-grade, and full-featured toolkit for the Transport Layer Security (TLS) and Secure Sockets Layer (SSL) protocols, and a general-purpose cryptography library. It's an essential command-line swiss-army knife for Blue Teams dealing with certificates, encryption, hashing, and secure connections.
* **Key Features/Why it's useful:**
    * **TLS/SSL Client/Server Testing:** (`s_client`, `s_server`) for checking configurations, cipher suites, and certificate details of secure services.
    * **Certificate Management:** Generating private keys (RSA, ECC), Certificate Signing Requests (CSRs), self-signed certificates, inspecting certificate files (X.509).
    * **Encryption/Decryption:** Symmetric encryption (AES, 3DES, etc.) and asymmetric encryption (using RSA/ECC keys).
    * **Hashing:** Calculating various cryptographic hashes (MD5, SHA1, SHA256, etc.).
    * **Encoding/Decoding:** Base64 encoding/decoding.
    * **Random Data Generation.**
* **Official Website/Repository:** [https://www.openssl.org/](https://www.openssl.org/)
* **Type:** CLI Cryptographic Toolkit & Library
* **Platform(s):** Linux, macOS, Windows, BSD, most Unix-like systems.
* **Installation:** Often pre-installed on Linux/macOS. Installers/packages available for most platforms. (Git Bash on Windows includes it).
    ```bash
    # Debian/Ubuntu
    sudo apt update && sudo apt install openssl
    # macOS (usually pre-installed, or via Homebrew)
    brew install openssl
    ```
* **Basic Usage Example:**
    ```bash
    # Check the certificate of a remote HTTPS server
    openssl s_client -connect [example.com:443](https://www.google.com/search?q=example.com:443) -showcerts </dev/null

    # View details of a certificate file
    openssl x509 -in certificate.crt -text -noout

    # Generate a 2048-bit RSA private key
    openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

    # Calculate SHA256 hash of a file
    openssl dgst -sha256 file.zip

    # Encrypt a file using AES-256-CBC (prompts for password)
    openssl enc -aes-256-cbc -salt -in plaintext.txt -out encrypted.enc

    # Decrypt the file (prompts for password)
    openssl enc -d -aes-256-cbc -in encrypted.enc -out decrypted.txt
    ```
* **Alternatives:** GnuTLS (CLI similar to OpenSSL), LibreSSL (fork), platform-specific tools (e.g., Keychain Access on macOS, Certificate Manager on Windows - for GUI management).
* **Notes/Tips:** OpenSSL has a vast number of commands and options; refer to the man pages (`man openssl`, `man s_client`, etc.) or online documentation. Essential for managing PKI and troubleshooting TLS issues.

---