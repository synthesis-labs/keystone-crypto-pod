//
//  OneTimeKey.swift
//  keystone
//
//  Created by Synthesis on 2018/08/27.
//  Copyright © 2018 Synthesis. All rights reserved.
//

import Foundation

public class OneTimeKey {
    var keyMaterial: [UInt8]
    var id : String

    public init(id: String, keyMaterialBase64: String) throws {
        do {
            self.id = id
            let bytes = keyMaterialBase64.base64Bytes
            guard bytes != nil else {
                throw KeystoneExceptions.InvalidInput(message: "Invalid base64 data for one time key")
            }
            self.keyMaterial = bytes!
        }
        catch let error {
            throw error
        }
    }

    public func getId() -> String {
        return id
    }

    func getKeyMaterial() -> [UInt8] {
        return keyMaterial
    }

}
