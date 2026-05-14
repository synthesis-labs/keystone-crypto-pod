# KeystoneCrypto

## Overview

KeystoneCrypto is a Swift library that provides secure cryptographic operations for iOS applications. It supports AES and Triple DES encryption with multiple block cipher modes, including PIN encryption and general-purpose data encryption.

## Features

- **Data Encryption/Decryption**: Encrypt and decrypt sensitive data using AES or Triple DES
- **PIN Encryption**: Secure PIN encryption using ISO 9564 standards
- **Local Key Generation**: Generate local encryption keys from one-time keys
- **Multiple Algorithms**: Support for both AES and Triple DES encryption
- **PKCS#7 Padding**: Automatic padding for data encryption
- **Random IV Generation**: Secure random initialization vectors for CBC mode

## Example

To run the example project, clone the repo, and run `pod install` from the Example directory first.

## Requirements

## Installation

KeystoneCrypto is available through [CocoaPods](https://cocoapods.org). To install
it, simply add the following lines to your Podfile:

```ruby
source 'https://github.com/synthesis-labs/keystone-crypto-pod.git' 
pod 'KeystoneCrypto'
```

## Usage

### Data Encryption and Decryption

#### Encrypting Data

The `encryptData()` method encrypts sensitive data using a local key. The encryption automatically handles:
- Key type detection (AES or Triple DES)
- Random IV generation
- PKCS#7 padding
- Base64 encoding of ciphertext and IV

```swift
import KeystoneCrypto

// Initialize KeystoneCrypto
let keystone = KeystoneCrypto()

// Get your local key (generated from a one-time key)
let oneTimeKey = ... // Your OneTimeKey object
let localKey = try keystone.generateLocalKey(oneTimeKey: oneTimeKey)

// Encrypt sensitive data
let sensitiveData = "Credit card number: 4532-1111-1111-1111"
do {
    let wrappedData = try keystone.encryptData(data: sensitiveData, key: localKey)
    print("Encryption successful!")
    print("Encrypted data: \(wrappedData.encryptedData.cipherText)")
    print("Encryption algorithm: \(wrappedData.encryptedData.alg)")
    print("IV: \(wrappedData.encryptedData.iv ?? "N/A")")
} catch {
    print("Encryption failed: \(error)")
}
```

**Algorithm Details:**
- **For AES Keys**: Uses AES encryption with a 16-byte random IV in CBC mode
- **For Triple DES Keys**: Uses 3DES encryption with an 8-byte random IV in CBC mode
- Both modes use PKCS#7 padding automatically

#### Decrypting Data

The `decryptData()` method decrypts data that was previously encrypted using `encryptData()`. It automatically:
- Detects the encryption algorithm from the key type
- Extracts and uses the stored IV
- Removes PKCS#7 padding
- Converts the plaintext back to a UTF-8 string

```swift
// Decrypt the encrypted data
do {
    let decryptedData = try keystone.decryptData(
        data: wrappedData.encryptedData, 
        key: localKey
    )
    print("Decryption successful!")
    print("Decrypted data: \(decryptedData)")
} catch {
    print("Decryption failed: \(error)")
}
```

#### Complete Encryption/Decryption Workflow

Here's a complete example showing the full workflow:

```swift
do {
    // Step 1: Generate a local key
    let localKey = try keystone.generateLocalKey(oneTimeKey: oneTimeKey)
    
    // Step 2: Encrypt sensitive data
    let originalData = "Payment details: Amount $1000.00"
    let wrappedData = try keystone.encryptData(data: originalData, key: localKey)
    
    // Step 3: Store or transmit the encrypted data
    let encryptedPayload = wrappedData.encryptedData.cipherText
    let encryptionIV = wrappedData.encryptedData.iv
    let algorithm = wrappedData.encryptedData.alg
    
    // Step 4: Later, decrypt the data
    let recoveredData = try keystone.decryptData(
        data: wrappedData.encryptedData,
        key: localKey
    )
    
    print("Original: \(originalData)")
    print("Recovered: \(recoveredData)")
    print("Match: \(originalData == recoveredData)")
    
} catch let error {
    print("Operation failed: \(error)")
}
```

### Data Structures

#### EncryptedData
Contains the encrypted payload information:
- `cipherText`: Base64-encoded encrypted content
- `iv`: Base64-encoded initialization vector (optional for ECB mode)
- `mode`: Cipher mode used (CBC or ECB)
- `alg`: Encryption algorithm used (AES128, DES3, etc.)

#### WrappedData
Contains the complete encryption result:
- `encryptedData`: The EncryptedData object with encryption details
- `clientKey`: The wrapped client key material
- `wrappingKeyId`: The ID of the wrapping key used

### Error Handling

Common exceptions that may be thrown:

```swift
do {
    let encryptedData = try keystone.encryptData(data: data, key: localKey)
} catch KeystoneExceptions.CryptoError {
    print("Cryptographic operation failed")
} catch KeystoneExceptions.InvalidInput {
    print("Invalid input parameters")
} catch {
    print("Unexpected error: \(error)")
}
```

## Author

kieron@synthesis.co.za

## License

KeystoneCrypto is available under the MIT license. See the LICENSE file for more info.

