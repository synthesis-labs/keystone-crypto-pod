//
//  EncryptedData.swift
//  keystone
//
//  Created by Synthesis on 2018/08/27.
//  Copyright © 2018 Synthesis. All rights reserved.
//

import Foundation

public class EncryptedData {
    private var cipherText: String
    private var iv: String?
    private var mode: BlockCipherMode
    private var alg: String

    public init(cipherText: String, iv: String?, mode: BlockCipherMode, alg: String) {
        self.cipherText = cipherText
        self.iv = iv
        self.mode = mode
        self.alg = alg
    }

    public func getCipherText() -> String {
        return cipherText
    }

    public func getIv() -> String? {
        return iv
    }

    public func getMode() -> BlockCipherMode {
        return mode
    }

    public func getAlg() -> String {
        return alg
    }
}
