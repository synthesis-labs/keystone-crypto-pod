//
//  Data_to_Hexstring.swift
//  keystone
//
//  Created by Synthesis on 2018/08/27.
//  Copyright © 2018 Synthesis. All rights reserved.
//

import Foundation

extension Data {
    var hexEncodedString: String {
        get {
            return map { String(format: "%02hhX", $0) }.joined() //for uppercase hex use "%02hhX"
        }
    }
}

extension Collection where Element == UInt8 {
    var data: Data {
        get {
            return Data(self)
        }
    }
    var hexEncodedString: String {
        get {
            return map{ String(format: "%02hhX", $0) }.joined()
        }
    }
}

extension String {
    
    var hexaBytes: [UInt8] {
        get {
            var position = startIndex
            return (0..<count/2).compactMap { _ in    // for Swift 4.1 or later use compactMap instead of flatMap
                defer { position = index(position, offsetBy: 2) }
                return UInt8(self[position...index(after: position)], radix: 16)
            }
        }
    }
    var hexaData: Data { get { return hexaBytes.data } }
    var base64Bytes: [UInt8]? {
        get {
            if let nsdata = NSData(base64Encoded: self, options: NSData.Base64DecodingOptions.ignoreUnknownCharacters)  {
                var bytes = [UInt8](repeating: 0, count: nsdata.length)
                nsdata.getBytes(&bytes,length: nsdata.length)
                return bytes
            }
            else {
                return nil
            }
        }
    }
    var isNumber: Bool {
        get {
            return !isEmpty && rangeOfCharacter(from: CharacterSet.decimalDigits.inverted) == nil
        }
    }
    
    func index(at position: Int, from start: Index? = nil) -> Index? {
        let startingIndex = start ?? startIndex
        return index(startingIndex, offsetBy: position, limitedBy: endIndex)
    }
    
    func character(at position: Int) -> Character? {
        guard position >= 0, let indexPosition = index(at: position) else {
            return nil
        }
        return self[indexPosition]
    }
    
    subscript (i: Int) -> Character {
        return self[index(startIndex, offsetBy: i)]
    }
    subscript (bounds: CountableRange<Int>) -> Substring {
        let start = index(startIndex, offsetBy: bounds.lowerBound)
        let end = index(startIndex, offsetBy: bounds.upperBound)
        return self[start ..< end]
    }
    subscript (bounds: CountableClosedRange<Int>) -> Substring {
        let start = index(startIndex, offsetBy: bounds.lowerBound)
        let end = index(startIndex, offsetBy: bounds.upperBound)
        return self[start ... end]
    }
    subscript (bounds: CountablePartialRangeFrom<Int>) -> Substring {
        let start = index(startIndex, offsetBy: bounds.lowerBound)
        let end = index(endIndex, offsetBy: -1)
        return self[start ... end]
    }
    subscript (bounds: PartialRangeThrough<Int>) -> Substring {
        let end = index(startIndex, offsetBy: bounds.upperBound)
        return self[startIndex ... end]
    }
    subscript (bounds: PartialRangeUpTo<Int>) -> Substring {
        let end = index(startIndex, offsetBy: bounds.upperBound)
        return self[startIndex ..< end]
    }
}

extension Substring {
    subscript (i: Int) -> Character {
        return self[index(startIndex, offsetBy: i)]
    }
    subscript (bounds: CountableRange<Int>) -> Substring {
        let start = index(startIndex, offsetBy: bounds.lowerBound)
        let end = index(startIndex, offsetBy: bounds.upperBound)
        return self[start ..< end]
    }
    subscript (bounds: CountableClosedRange<Int>) -> Substring {
        let start = index(startIndex, offsetBy: bounds.lowerBound)
        let end = index(startIndex, offsetBy: bounds.upperBound)
        return self[start ... end]
    }
    subscript (bounds: CountablePartialRangeFrom<Int>) -> Substring {
        let start = index(startIndex, offsetBy: bounds.lowerBound)
        let end = index(endIndex, offsetBy: -1)
        return self[start ... end]
    }
    subscript (bounds: PartialRangeThrough<Int>) -> Substring {
        let end = index(startIndex, offsetBy: bounds.upperBound)
        return self[startIndex ... end]
    }
    subscript (bounds: PartialRangeUpTo<Int>) -> Substring {
        let end = index(startIndex, offsetBy: bounds.upperBound)
        return self[startIndex ..< end]
    }
}
