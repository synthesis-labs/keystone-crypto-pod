//
//  Pinblock.swift
//  keystone
//
//  Created by Synthesis on 2018/08/27.
//  Copyright © 2018 Synthesis. All rights reserved.
//

import Foundation

public class Pinblock {
    public enum PinblockFormat: String {
        case AES_ISO95641_4 = "48"
        case DES_ISO95641_ANSIX98_0 = "01"
    }

    private var encryptedPinblock: String
    private var encryptedZPK: String?
    private var wrappingKeyId: String?
    private var zpkKCV: String?
    private var pan: String
    private var format: PinblockFormat

    init(encryptedPinblock: String, encryptedZPK: String?, zpkKCV: String?, wrappingKeyId: String?, pan: String, format: PinblockFormat) {
        self.encryptedPinblock = encryptedPinblock
        self.encryptedZPK = encryptedZPK
        self.wrappingKeyId = wrappingKeyId
        self.zpkKCV = zpkKCV
        self.pan = pan
        self.format = format
    }
    
    public convenience init(encryptedPinblock: String, pan: String, format: PinblockFormat) {
        self.init(encryptedPinblock: encryptedPinblock, encryptedZPK: nil, zpkKCV: nil, wrappingKeyId: nil, pan: pan, format: format)
    }

    public func getEncryptedPinblock() -> String {
        return encryptedPinblock
    }

    public func getEncryptedZPK() -> String?{
        return encryptedZPK
    }

    public func getWrappingKeyId() -> String? {
        return wrappingKeyId
    }
    
    public func getZpkKCV() -> String? {
        return zpkKCV
    }
    
    public func getPAN() -> String? {
        return pan
    }
    
    public func getFormat() -> PinblockFormat {
        return format;
    }
}
