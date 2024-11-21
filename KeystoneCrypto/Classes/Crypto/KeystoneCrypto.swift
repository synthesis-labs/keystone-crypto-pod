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
    /// 
    /// - Returns: 
    ///   `LocalKey` - The generated LocalKey.
    /// 
    /// - Throws: 
    ///   Any errors encountered during key generation.
    public func GenerateLocalKey(
        otk: OneTimeKey,
        keyType: LocalKey.KeyType = LocalKey.KeyType.TripleDES
    ) throws -> LocalKey {
        do {
            let key = try LocalKey(wrappingKey: otk, keyType: keyType)
            return key
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
        pinhalf.append(String(pin.count))
        pinhalf.append(pin)
        pinhalf.append(String(repeating: "A", count: 16 - pinhalf.count))
        pinhalf.append(RandomString(length: 16))

        var panhalf = String(pan.count - 1 - 12)
        let indexStartOfPan = pan.index(at: 0)!
        let indexEndOfPan = pan.index(at: pan.count - 1)!
        panhalf.append(String(pan[indexStartOfPan..<indexEndOfPan]))
        panhalf.append(String(repeating: "0", count: 32 - panhalf.count))

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

        var panhalf = String(pan!.count - 1 - 12)
        let indexStartOfPan = pan!.index(at: 0)!
        let indexEndOfPan = pan!.index(at: pan!.count - 1)!
        panhalf.append(String(pan![indexStartOfPan..<indexEndOfPan]))
        panhalf.append(String(repeating: "0", count: 32 - panhalf.count))

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

    public func EncryptData(data: String, key: LocalKey, mode: BlockCipherMode) throws -> WrappedData {
        let algorithm: Cryptor.Algorithm
        var iv: [UInt8]
        let returnAlg: String
        do {
            if key.getKeyType() == LocalKey.KeyType.TripleDES {
                algorithm = Cryptor.Algorithm.tripleDES
                iv = try GenerateRandomKeyBytes(len: 8)
                returnAlg = "DES3"
            } else {
                algorithm = Cryptor.Algorithm.aes
                iv = try GenerateRandomKeyBytes(len: 16)
                returnAlg = "AES128"
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
