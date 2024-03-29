//
//  LocalKey.swift
//  keystone
//
//  Created by Synthesis on 2018/08/27.
//  Copyright © 2018 Synthesis. All rights reserved.
//

import Foundation
import Security
import IDZSwiftCommonCrypto

public class LocalKey {
    public enum KeyType {
        case AES
        case TripleDES
    }
    
    private var localKey: [UInt8]!
    private var encryptedKeyMaterial : String!
    private var wrappingKey : OneTimeKey!
    private var publicKey : SecKey!
    private var kcv: String!
    private var keyType: KeyType = KeyType.TripleDES
    
    public init(wrappingKey: OneTimeKey, keyType: KeyType = KeyType.TripleDES) throws {
        self.keyType = keyType
        self.wrappingKey = wrappingKey
        do {
            try self.publicKey = LoadPublicKey(wrappingKey: wrappingKey)
            try self.localKey = GenerateLocalKey(keyType: keyType)
            try self.encryptedKeyMaterial = EncryptLocalKey(localKey: self.localKey, pubKey: self.publicKey)
            try self.kcv = CalculateKCV(localKey: self.localKey)
        }
        catch let error {
            throw error
        }
    }
    
    public func getEncryptedKeyMaterial() -> String {
        return encryptedKeyMaterial
    }

    public func getWrappingKey() -> OneTimeKey {
        return wrappingKey
    }

    public func getKey() -> [UInt8] {
        return localKey
    }
    
    public func getKCV() -> String {
        return kcv
    }
    
    public func getKeyType() -> KeyType {
        return keyType
    }

    private func LoadPublicKey(wrappingKey: OneTimeKey) throws -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrIsPermanent as String: false
        ]
        let data = Data(base64Encoded: wrappingKey.getKeyMaterial())!
        var error: Unmanaged<CFError>?
        guard let pubKey = SecKeyCreateWithData(data as CFData,
                                                attributes as CFDictionary,
                                                &error) as SecKey? else {
            throw error!.takeRetainedValue() as Error
        }
        
        return pubKey
    }
    
    private func CalculateKCV(localKey: [UInt8]) throws -> String {
        if (self.keyType == KeyType.TripleDES) {
            let kcvData = [UInt8](repeating: 0, count: 16)
            
            //Encrypt pinhalf using DES key
            let cryptor = Cryptor(
                operation: .encrypt,
                algorithm: .tripleDES,
                mode: .ECB,
                padding: .NoPadding,
                key: localKey,
                iv: Array<UInt8>()
            )
            let result = cryptor.update(buffer: kcvData, byteCount: kcvData.count)
            guard result != nil, result!.final() != nil else {
                throw KeystoneExceptions.CryptoError(message: "Error calculating KCV")
            }
            let encryptedPinBlock = result!.final()!
            let kcv = String(encryptedPinBlock.hexEncodedString[..<6])
            
            return kcv
        }
        else {
            return "000000"
        }
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
    
    private func GenerateLocalKey(keyType : KeyType) throws -> [UInt8] {
        let key : [UInt8]
        do {
            if keyType == KeyType.AES {
                try key = GenerateRandomKeyBytes(len: 32)
            } else {
                try key = GenerateRandomKeyBytes(len: 24)
            }
        }
        catch let error {
            throw error
        }
        
        return key
    }

    private func EncryptLocalKey(localKey: [UInt8], pubKey: SecKey) throws -> String {
        let algorithm: SecKeyAlgorithm = .rsaEncryptionOAEPSHA1
        var error: Unmanaged<CFError>?
        guard let cipherText = SecKeyCreateEncryptedData(publicKey,
                                                         algorithm,
                                                         Data(localKey) as CFData,
                                                         &error) as Data? else {
                                                            throw error!.takeRetainedValue() as Error
        }
        
        return cipherText.base64EncodedString()
        
    }
}
