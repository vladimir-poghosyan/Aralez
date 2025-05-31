# Aralez: A Privacy-Focused Secret Manager

Aralez is a minimal, privacy-oriented secret manager designed to store and manage encrypted text-based secrets entirely within a single HTML file directly in the browser — no servers, no tracking, no third-party libraries. Utilizing the [WebCrypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API), Aralez ensures that all cryptographic operations are performed locally in your browser, with no unencrypted data ever leaving your device.

## Disclaimer

Aralez is intended as a minimal, privacy-focused secret manager for individuals who prefer not to rely on cloud-based solutions. It is not intended to replace industry-standard password managers and should be used with caution. Always ensure you have backups of your encrypted secrets and remember your PINs, as recovery options are limited.

## Key Features

* Client-side encryption only — nothing unencrypted ever leaves your machine

* Each secret is protected by its own PIN (minimum 12 characters)

* TOTP generation supported for OTP-based authentication

* Single-file HTML — everything, including the data, is stored in the same file

* Search and sort secrets

* Mobile-friendly, responsive interface

* Offline capable — works entirely without internet access

* Optional server sync — sync encrypted data via aralez.py or custom backend

* Easy backup — just save the .html file

## Getting Started
### Running Locally

1. Download the [aralez.html](https://github.com/vladimir-poghosyan/Aralez/blob/main/aralez.html) file from the GitHub repository.

2. Open the file in a web browser (JavaScript must be enabled).
   
3. When first opened, Aralez will generate a salt and warn that it must be saved and reloaded to ensure proper security.

4. Follow the on-screen instructions to create and manage your secrets.

### Hosting Online

* Host the [aralez.html](https://github.com/vladimir-poghosyan/Aralez/blob/main/aralez.html) file on your preferred web server.

* Optionally, deploy the provided `aralez.py` utility to handle server-side synchronization or use your own implementation.

* Access your secrets from any device with a compatible browser.

In this mode, Aralez can:

* Sync encrypted secrets via HTTP `PUT` to the same URL path.

* Use your own auth mechanism to protect access.

See [aralez.py](https://github.com/vladimir-poghosyan/Aralez/blob/main/aralez.py) for a simple reference implementation.

## Security Considerations

* Each secret is encrypted using AES-GCM and a key derived from your PIN using a salted KDF.

* Salt is automatically generated and embedded on first use — **you must save the updated file and reload it** before using Aralez securely.

* Aralez does not track you, send data to the cloud, or use third-party libraries — it's entirely self-contained.

* There is no master recovery key — forgetting your PIN means permanent data loss.

* Use strong, memorable PINs (12+ characters) and back up your .html file securely.

* No External Dependencies: Aralez does not use any third-party libraries, reducing potential attack surfaces.
