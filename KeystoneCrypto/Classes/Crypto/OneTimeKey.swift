//
//  OneTimeKey.swift
//  keystone
//
//  Created by Synthesis on 2018/08/27.
//  Copyright © 2018 Synthesis. All rights reserved.
//

import Foundation

public class OneTimeKey {
    var keyMaterial: String
    var id : String

    public init(id: String, keyMaterialBase64: String) {
        self.id = id
        self.keyMaterial = keyMaterialBase64
    }

    public func getId() -> String {
        return id
    }

    func getKeyMaterial() -> String {
        return keyMaterial
    }

}
