//
//  Pinblock.swift
//  keystone
//
//  Created by Synthesis on 2018/08/27.
//  Copyright © 2018 Synthesis. All rights reserved.
//

import Foundation

public class Pinblock {

    private var encryptedPinblock: String
    private var encryptedZPK: String
    private var wrappingKeyId: String
    private var zpkKCV: String
    private var pan: String?

    public init(encryptedPinblock: String, encryptedZPK: String, zpkKCV: String, wrappingKeyId: String, pan: String? = nil) {
        self.encryptedPinblock = encryptedPinblock
        self.encryptedZPK = encryptedZPK
        self.wrappingKeyId = wrappingKeyId
        self.zpkKCV = zpkKCV
        self.pan = pan
    }

    public func getEncryptedPinblock() -> String {
        return encryptedPinblock
    }

    public func getEncryptedZPK() -> String{
        return encryptedZPK
    }

    public func getWrappingKeyId() -> String {
        return wrappingKeyId
    }
    
    public func getZpkKCV() -> String {
        return zpkKCV
    }
    
    public func getPAN() -> String? {
        return pan
    }
}
