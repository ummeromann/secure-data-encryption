# Secure Data Encryption System

This project is a Python-based encryption system built using **Streamlit**. It provides secure data encryption with passkey-protected storage, data decryption, failed attempt handling, and in-memory storage.

## Features

- **Data Encryption:** Encrypts sensitive data using a passkey.
- **Data Decryption:** Decrypts encrypted data using the correct passkey.
- **Passkey Protection:** The system only allows access to the encrypted data if the correct passkey is provided.
- **Failed Attempt Handling:** Limits the number of failed attempts to protect against brute-force attacks.
- **In-memory Storage:** The encrypted data is temporarily stored in memory, providing secure access without saving it on disk.
