//
//  KeystoneException.swift
//  keystone
//
//  Created by Synthesis on 2018/08/27.
//  Copyright © 2018 Synthesis. All rights reserved.
//

import Foundation

public enum KeystoneExceptions : Error {
    case InvalidInput(message: String)
    case CryptoError(message: String)
    case InvalidPinblockException(message: String)
    case InvalidOneTimeKeyException(message: String)
    case InvalidLocalKeyException(message: String)
}
