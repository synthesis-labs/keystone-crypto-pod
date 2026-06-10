//
//  KeystoneCrypto.swift
//  keystone
//
//  Created by Synthesis on 2018/08/27.
//  Copyright © 2018 Synthesis. All rights reserved.
//

import Foundation
import Security
import IDZSwiftCommonCrypto

public enum BlockCipherMode: String {
    case ECB
    case CBC
}

public class KeystoneCrypto {

    public init() {

    }

    /// Generates a local key.
    /// The key type can be specified, defaulting to TripleDES if not provided.
    /// 
    /// - Parameters:
    ///   - otk: `OneTimeKey` - The one-time key object.
    ///   - keyType: `LocalKey.KeyType` - The type of key to generate, defaulting to `LocalKey.KeyType.TripleDES`.
    ///   - oaepHah: `OaepHash` - The padding scheme to be used, defaulting to `OaepHash.sha1`
    ///
    /// - Returns: 
    ///   `LocalKey` - The generated LocalKey.
    /// 
    /// - Throws: 
    ///   Any errors encountered during key generation.
    @available(*, deprecated, renamed: "generateLocalKey()", message: "This method will no longer be supported in the future.")
    public func GenerateLocalKey(
        otk: OneTimeKey,
        keyType: LocalKey.KeyType = LocalKey.KeyType.TripleDES,
        oaepHash: OaepHash = OaepHash.sha1
    ) throws -> LocalKey {
        do {
            let key = try LocalKey(wrappingKey: otk, keyType: keyType, oaepHash: oaepHash)
            return key
        } catch let error {
            throw error
        }
    }
    
    
    /// Generates a local key.
    /// Generates an AES key and uses SHA256 for OAEP
    ///
    /// - Parameters:
    ///   - otk: `OneTimeKey` - The one-time key object.
    ///
    /// - Returns:
    ///   `LocalKey` - The generated LocalKey.
    ///
    /// - Throws:
    ///   Any errors encountered during key generation.
    public func generateLocalKey(oneTimeKey: OneTimeKey) throws -> LocalKey { try GenerateLocalKey(otk: oneTimeKey, keyType: LocalKey.KeyType.AES, oaepHash: OaepHash.sha256 )}

    /// Encrypts a PIN.
    /// 
    /// - Parameters:
    ///   - pin: `String` -  The PIN to encrypt.
    ///   - key: `LocalKey` -  - The local key used for encryption.
    ///   - pan: `String` - The Primary Account Number (PAN).
    /// 
    /// - Returns: 
    ///   `Pinblock` - The encrypted Pinblock.
    /// 
    /// - Throws: 
    ///   `KeystoneExceptions.InvalidInput` if the PIN is not between 4 and 12 digits or 
    ///    contains non-numeric characters.
    ///   Any other errors encountered during encryption.
    @available(*, deprecated, renamed: "encryptPin()", message: "This method will no longer be supported in the future.")
    public func EncryptPin(pin: String, key: LocalKey, pan: String = "1234567890123456") throws -> Pinblock {
        do {
            guard pin.count >= 4, pin.count <= 12, pin.isNumber else {
                throw KeystoneExceptions.InvalidInput(message: "PIN must be between 4 and 12 decimal characters")
            }

            let pinblock: Pinblock

            if key.getKeyType() == LocalKey.KeyType.TripleDES {
                pinblock = try DESPinToPinblock(pin: pin, key: key, pan: pan)
            } else {
                pinblock = try AESPinToPinblock(pin: pin, key: key, pan: pan)
            }

            return pinblock
        } catch let error {
            throw error
        }
    }
    
    /// Encrypts a PIN.
    ///
    /// - Parameters:
    ///   - pin: `String` -  The PIN to encrypt.
    ///   - key: `LocalKey` -  - The local key used for encryption.
    ///   - pan: `String` - The Primary Account Number (PAN).
    ///
    /// - Returns:
    ///   `Pinblock` - The encrypted Pinblock.
    ///
    /// - Throws:
    ///   `KeystoneExceptions.InvalidInput` if the PIN is not between 4 and 12 digits or
    ///    contains non-numeric characters.
    ///   Any other errors encountered during encryption.
    public func encryptPin(pin: String, key: LocalKey, pan: String = "1234567890123456") throws -> Pinblock { try EncryptPin(pin: pin, key: key, pan: pan)}

    /// Decrypts a PIN from the provided Pinblock.
    /// 
    /// - Parameters:
    ///   - pinblock: `Pinblock` - An object containing encrypted PIN data.
    ///   - key: `LocalKey` - The local key used for decryption.
    /// 
    /// - Returns: 
    ///   `String` - The decrypted PIN.
    /// 
    /// - Throws: 
    ///   Any errors encountered during decryption.
    @available(*, deprecated, renamed: "decryptPin()", message: "This method will no longer be supported in the future.")
    public func DecryptPinblock(pinblock: Pinblock, key: LocalKey) throws -> String {
        do {
            let pin: String

            if key.getKeyType() == LocalKey.KeyType.TripleDES {
                pin = try DESPinblockToPin(pinblock: pinblock, key: key)
            } else {
                pin = try AESPinblockToPin(pinblock: pinblock, key: key)
            }

            return pin

        } catch let error {
            throw error
        }
    }
    
    /// Decrypts a PIN from the provided Pinblock.
    ///
    /// - Parameters:
    ///   - pinblock: `Pinblock` - An object containing encrypted PIN data.
    ///   - key: `LocalKey` - The local key used for decryption.
    ///
    /// - Returns:
    ///   `String` - The decrypted PIN.
    ///
    /// - Throws:
    ///   Any errors encountered during decryption.
    public func decryptPin(pinblock: Pinblock, key: LocalKey) throws -> String { try DecryptPinblock(pinblock: pinblock, key: key)}

    private func RandomString(length: Int) -> String {

        let hexArray: NSString = "0123456789ABCDEF"

        var randomString = ""

        for _ in 0 ..< length {
            let rand = Int.random(in: 1..<hexArray.length)
            var nextChar = hexArray.character(at: rand)
            randomString += NSString(characters: &nextChar, length: 1) as String
        }

        return randomString
    }

    private func DESPinToPinblock(pin: String, key: LocalKey, pan: String) throws -> Pinblock {
        guard pan.count >= 13, pan.isNumber else {
            throw KeystoneExceptions.InvalidInput(message: "PAN must be at least 13 decimal characters")
        }

        var panhalf = "0000"
        let indexStartOfPan = pan.index(at: pan.count - 1 - 12)!
        let indexEndOfPan = pan.index(at: pan.count - 1)!
        panhalf.append(String(pan[indexStartOfPan..<indexEndOfPan]))
        let panbytes = panhalf.hexaData

        var pinhalf = "0"
        pinhalf.append(String(pin.count))
        pinhalf.append(pin)
        pinhalf.append(String(repeating: "F", count: 16 - pinhalf.count))
        let pinbytes = pinhalf.hexaData

        var clearPinblock = [UInt8]()
        for (index, item) in (panbytes.enumerated()) {
            clearPinblock.append(item ^ pinbytes[index])
        }

        let cryptor = Cryptor(
            operation: .encrypt,
            algorithm: .tripleDES,
            mode: .ECB,
            padding: .NoPadding,
            key: key.getKey(),
            iv: [UInt8]()
        )
        let result = cryptor.update(byteArray: clearPinblock)
        guard result != nil, result!.final() != nil else {
            throw KeystoneExceptions.CryptoError(message: "Error encrypting pin block")
        }
        let encryptedPinBlock = result!.final()!

        let data = NSData(bytes: encryptedPinBlock, length: encryptedPinBlock.count)
        let base64Data = data.base64EncodedString(options: NSData.Base64EncodingOptions.endLineWithLineFeed)
        let pb = Pinblock(
            encryptedPinblock: base64Data,
            encryptedZPK: key.getEncryptedKeyMaterial(),
            zpkKCV: key.getKCV(),
            wrappingKeyId: key.getWrappingKey().getId(),
            pan: pan,
            format: Pinblock.PinblockFormat.DES_ISO95641_ANSIX98_0
        )

        return pb
    }

    private func DESPinblockToPin(pinblock: Pinblock, key: LocalKey) throws -> String {
        let cryptor = Cryptor(
            operation: .decrypt,
            algorithm: .tripleDES,
            mode: .ECB,
            padding: .NoPadding,
            key: key.getKey(),
            iv: [UInt8]()
        )

        let data = Data(base64Encoded: pinblock.getEncryptedPinblock())
        let result = cryptor.update(data: data!)
        guard result != nil, result!.final() != nil else {
            throw KeystoneExceptions.CryptoError(message: "Error decrypting pin block")
        }
        let clearPinblock = result!.final()!

        var panhalf = "0000"
        let indexStartOfPan = pinblock.getPAN()!.index(at: pinblock.getPAN()!.count - 1 - 12)!
        let indexEndOfPan = pinblock.getPAN()!.index(at: pinblock.getPAN()!.count - 1)!
        panhalf.append(String(pinblock.getPAN()![indexStartOfPan..<indexEndOfPan]))
        let panbytes = panhalf.hexaData

        var pinbytes = [UInt8]()
        for (index, item) in (panbytes.enumerated()) {
            pinbytes.append(item ^ clearPinblock[index])
        }
        let pinhalf = pinbytes.hexEncodedString

        let pinLen = Int(String(pinhalf.character(at: 1)!))!

        let indexStartOfPinblock = pinhalf.index(pinhalf.startIndex, offsetBy: 2) // from 2 to read pin
        let indexEndOfText = pinhalf.index(indexStartOfPinblock, offsetBy: pinLen)

        let clearPin = String(pinhalf[indexStartOfPinblock..<indexEndOfText])

        return clearPin
    }

    private func AESPinToPinblock(pin: String, key: LocalKey, pan: String) throws -> Pinblock {
        guard pan.isNumber else {
            throw KeystoneExceptions.InvalidInput(message: "PAN must be at least 12 decimal characters")
        }

        var pinhalf = "4"
        pinhalf.append(String(pin.count, radix: 16, uppercase: true))
        pinhalf.append(pin)
        pinhalf.append(String(repeating: "A", count: 14 - pin.count)) // pin starts at index 2
        pinhalf.append(RandomString(length: 16))

        let M = String(pan.count - 12, radix: 16, uppercase: true)
        let panhalf =  M + pan + String(repeating: "0", count: 31 - pan.count);

        // Encrypt pinhalf using AES key
        let cryptor = Cryptor(
            operation: .encrypt,
            algorithm: .aes,
            mode: .ECB,
            padding: .NoPadding,
            key: key.getKey(),
            iv: [UInt8]()
        )
        var result = cryptor.update(data: pinhalf.hexaData)
        guard result != nil, result!.final() != nil else {
            throw KeystoneExceptions.CryptoError(message: "Error encrypting pinblock")
        }
        let intermediateValue1 = result!.final()!

        // Intermediate block A is then XOR'd with PAN block
        let panhalfArr = panhalf.hexaData
        var xor = [UInt8]()

        for (index, item) in (intermediateValue1.enumerated()) {
            xor.append(item ^ panhalfArr[index])
        }

        // Intermediate block B is the enciphered with AES key again
        let cryptor2 = Cryptor(
            operation: .encrypt,
            algorithm: .aes,
            mode: .ECB,
            padding: .NoPadding,
            key: key.getKey(),
            iv: [UInt8]()
        )
        result = cryptor2.update(byteArray: xor)
        guard result != nil, result!.final() != nil else {
            throw KeystoneExceptions.CryptoError(message: "Error encrypting pinblock")
        }
        let intermediateValue2 = result!.final()!

        let data = NSData(bytes: intermediateValue2, length: intermediateValue2.count)
        let base64Data = data.base64EncodedString(options: NSData.Base64EncodingOptions.endLineWithLineFeed)
        let pb = Pinblock(
            encryptedPinblock: base64Data,
            encryptedZPK: key.getEncryptedKeyMaterial(),
            zpkKCV: key.getKCV(),
            wrappingKeyId: key.getWrappingKey().getId(),
            pan: pan,
            format: Pinblock.PinblockFormat.AES_ISO95641_4
        )

        return pb
    }

    private func AESPinblockToPin(pinblock: Pinblock, key: LocalKey) throws -> String {
        let pan = pinblock.getPAN()
        guard pan != nil, pan!.isNumber, pan!.count >= 12 else {
            throw KeystoneExceptions.InvalidInput(
                message: "PAN is required for an AES pinblock to be decrypted." +
                    "PAN must be at least 12 decimal characters"
            )
        }
        
        let M = String(pan!.count - 12, radix: 16, uppercase: true)
        let panhalf =  M + pan! + String(repeating: "0", count: 31 - pan!.count);

        let cryptor = Cryptor(
            operation: .decrypt,
            algorithm: .aes,
            mode: .ECB,
            padding: .NoPadding,
            key: key.getKey(),
            iv: [UInt8]()
        )

        let data = pinblock.getEncryptedPinblock().base64Bytes
        guard data != nil else {
            throw KeystoneExceptions.InvalidPinblockException(message: "Encrypted pinblock is not valid base64")
        }

        var result = cryptor.update(byteArray: data!)
        guard result != nil, result!.final() != nil else {
            throw KeystoneExceptions.CryptoError(message: "Error encrypting pinblock")
        }
        let decryptedPinblockBytes = result!.final()!

        let panhalfArr = panhalf.hexaData
        var xor = [UInt8]()
        for (index, item) in (decryptedPinblockBytes.enumerated()) {
            xor.append(item ^ panhalfArr[index])
        }

        let cryptor2 = Cryptor(
            operation: .decrypt,
            algorithm: .aes,
            mode: .ECB,
            padding: .NoPadding,
            key: key.getKey(),
            iv: [UInt8]()
        )
        result = cryptor2.update(byteArray: xor)
        guard result != nil, result!.final() != nil else {
            throw KeystoneExceptions.CryptoError(message: "Error encrypting pinblock")
        }
        let intermediateValue2 = result!.final()!
        let decryptedString = intermediateValue2.hexEncodedString

        let pinLen = Int(String(decryptedString.character(at: 1)!))!

        let indexStartOfPinblock = decryptedString.index(decryptedString.startIndex, offsetBy: 2) // from 2 to read pin
        let indexEndOfText = decryptedString.index(indexStartOfPinblock, offsetBy: pinLen)

        let clearPin = String(decryptedString[indexStartOfPinblock..<indexEndOfText])

        return clearPin
    }
    
    /// Encrypts sensitive data using the provided local key.
    ///
    /// This method encrypts a string of data using AES or Triple DES encryption with CBC mode.
    /// The encryption process automatically:
    /// - Generates a random Initialization Vector (IV) appropriate for the key type
    /// - Applies PKCS#7 padding to the plaintext
    /// - Returns wrapped data containing the encrypted content and key material
    ///
    /// **Algorithm Selection:**
    /// - If the key is AES: Uses AES encryption with a 16-byte IV
    /// - If the key is TripleDES: Uses 3DES encryption with an 8-byte IV
    ///
    /// **Usage Example:**
    /// ```swift
    /// let plaintext = "Sensitive payment information"
    /// do {
    ///     let wrappedData = try keystone.encryptData(data: plaintext, key: localKey)
    ///     print("Encrypted data: \(wrappedData.encryptedData.cipherText)")
    /// } catch {
    ///     print("Encryption failed: \(error)")
    /// }
    /// ```
    ///
    /// - Parameters:
    ///   - data: `String` - The plaintext data to encrypt. Can contain any UTF-8 characters.
    ///   - key: `LocalKey` - The local key to use for encryption. Must be generated using `generateLocalKey()`.
    ///
    /// - Returns:
    ///   `WrappedData` - An object containing:
    ///   - `encryptedData`: The encrypted payload with ciphertext, IV, mode, and algorithm
    ///   - `clientKey`: The wrapped client key material
    ///   - `wrappingKeyId`: The ID of the wrapping key used
    ///
    /// - Throws:
    ///   `KeystoneExceptions.CryptoError` if encryption fails
    ///   Any other errors encountered during the encryption process.
    ///
    /// - Note: The method uses CBC mode by default for enhanced security.
    public func encryptData(data: String, key: LocalKey) throws -> WrappedData { try EncryptData(data: data , key: key, mode: BlockCipherMode.CBC)}

    @available(*, deprecated, renamed: "encryptData()", message: "This method will no longer be supported in the future.")
    public func EncryptData(data: String, key: LocalKey, mode: BlockCipherMode) throws -> WrappedData {
        let algorithm: Cryptor.Algorithm
        var iv: [UInt8]
        let returnAlg: Algorithm
        do {
            if key.getKeyType() == LocalKey.KeyType.TripleDES {
                algorithm = Cryptor.Algorithm.tripleDES
                iv = try GenerateRandomKeyBytes(len: 8)
                returnAlg = Algorithm.DES3
            } else {
                algorithm = Cryptor.Algorithm.aes
                iv = try GenerateRandomKeyBytes(len: 16)
                returnAlg = Algorithm.AES128
            }
        } catch let error {
            throw error
        }

        var returnIv: String? = Data(iv).base64EncodedString()
        let actualMode: Cryptor.Mode
        if mode == BlockCipherMode.CBC {
            actualMode = Cryptor.Mode.CBC
        } else {
            actualMode = Cryptor.Mode.ECB
            iv = [UInt8]()
            returnIv = nil
        }

        let padding: UInt8 = UInt8(16 - (data.lengthOfBytes(using: String.Encoding.utf8) % 16))

        let paddedData = Array(data.utf8) + [UInt8](repeating: padding, count: Int(padding))

        let cryptor = Cryptor(
            operation: .encrypt,
            algorithm: algorithm,
            mode: actualMode,
            padding: .NoPadding,
            key: key.getKey(),
            iv: iv
        )

        let result = cryptor.update(byteArray: paddedData)
        guard result != nil, result!.final() != nil else {
            throw KeystoneExceptions.CryptoError(message: "Error encrypting data")
        }

        let cipherText: [UInt8] = result!.final()!

        return WrappedData(
            encryptedData: EncryptedData(
                cipherText: Data(cipherText).base64EncodedString(),
                iv: returnIv,
                mode: mode,
                alg: returnAlg
            ),
            clientKey: key.getWrappedClientKey(),
            wrappingKeyId: key.getWrappingKey().getId()
        )
    }
    
    /// Decrypts encrypted data using the provided local key.
    ///
    /// This method decrypts data that was previously encrypted using the `encryptData()` method.
    /// The decryption process:
    /// - Extracts the IV from the encrypted data payload
    /// - Decrypts the ciphertext using the appropriate algorithm (AES or Triple DES)
    /// - Removes PKCS#7 padding from the plaintext
    /// - Returns the original plaintext string
    ///
    /// **Algorithm Detection:**
    /// The method automatically determines the encryption algorithm (AES or 3DES) based on the key type
    /// and uses the corresponding decryption algorithm and IV size.
    ///
    /// **Usage Example:**
    /// ```swift
    /// do {
    ///     let plaintext = try keystone.decryptData(data: wrappedData.encryptedData, key: localKey)
    ///     print("Decrypted data: \(plaintext)")
    /// } catch {
    ///     print("Decryption failed: \(error)")
    /// }
    /// ```
    ///
    /// - Parameters:
    ///   - data: `EncryptedData` - The encrypted data object containing:
    ///     - `cipherText`: Base64-encoded encrypted content
    ///     - `iv`: Base64-encoded initialization vector (required for CBC mode)
    ///     - `mode`: The cipher mode used (CBC or ECB)
    ///     - `alg`: The encryption algorithm used (AES128, DES3, etc.)
    ///   - key: `LocalKey` - The local key to use for decryption. Must be the same key used for encryption.
    ///
    /// - Returns:
    ///   `String` - The decrypted plaintext data as UTF-8 string.
    ///
    /// - Throws:
    ///   `KeystoneExceptions.CryptoError` if:
    ///     - The ciphertext is not valid Base64
    ///     - The IV is missing or invalid
    ///     - Decryption fails during the cipher operations
    ///     - The decrypted data cannot be decoded as UTF-8
    ///   Any other errors encountered during the decryption process.
    ///
    /// - Note: This method only works with data encrypted using the `encryptData()` method.
    ///   The key used for decryption must match the key used for encryption.
    public func decryptData(data: EncryptedData, key: LocalKey) throws -> String { try DecryptData(data: data, key: key)}

    @available(*, deprecated, renamed: "decryptData", message: "This method will no longer be supported in the future.")
    public func DecryptData(data: EncryptedData, key: LocalKey) throws -> String {
        let algorithm: Cryptor.Algorithm
        var iv: [UInt8]

        if key.getKeyType() == LocalKey.KeyType.TripleDES {
            algorithm = Cryptor.Algorithm.tripleDES
        } else {
            algorithm = Cryptor.Algorithm.aes
        }

        let actualMode: Cryptor.Mode
        if data.getMode() == BlockCipherMode.CBC {
            actualMode = Cryptor.Mode.CBC
            guard data.getIv() != nil, let _iv = Data(base64Encoded: data.getIv()!) else {
                throw KeystoneExceptions.CryptoError(message: "Error decrypting data, missing IV")
            }
            iv = [UInt8](_iv)
        } else {
            actualMode = Cryptor.Mode.ECB
            iv = [UInt8]()
        }

        let cryptor = Cryptor(
            operation: .decrypt,
            algorithm: algorithm,
            mode: actualMode,
            padding: .NoPadding,
            key: key.getKey(),
            iv: iv
        )

        guard let cipherText = Data(base64Encoded: data.getCipherText()) else {
            throw KeystoneExceptions.CryptoError(message: "Error decrypting data, missing cipher text")
        }

        let result = cryptor.update(data: cipherText)
        guard result != nil, result!.final() != nil else {
            throw KeystoneExceptions.CryptoError(message: "Error decrypting data")
        }

        var plainTextBinary = result!.final()!
        let amountOfPadding = Int(plainTextBinary.last!)

        plainTextBinary.removeLast(amountOfPadding)
        guard let returnVal = String(bytes: plainTextBinary, encoding: .utf8) else {
            throw KeystoneExceptions.CryptoError(message: "Error decrypting data")
        }
        return returnVal
    }

    private func GenerateRandomKeyBytes(len: Int) throws -> [UInt8] {
        var keyData = Data(count: Int(len))

        let result = try keyData.withUnsafeMutableBytes { (mutableBytes: UnsafeMutableRawBufferPointer) -> Int32 in
            if mutableBytes.baseAddress == nil {
                throw KeystoneExceptions.CryptoError(message: "Error generating random key")
            }
            return SecRandomCopyBytes(kSecRandomDefault, len, mutableBytes.baseAddress!)
        }

        if result == errSecSuccess {
            return keyData.base64EncodedString().base64Bytes!
        } else {
            throw KeystoneExceptions.CryptoError(message: "Error generating random key")
        }
    }

}
