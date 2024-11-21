import Foundation
import KeystoneCrypto

extension NSDictionary {
    var swiftDictionary: [String: Any] {
        var swiftDictionary = [String: Any]()

        for key: Any in self.allKeys {
            let stringKey = key as! String
            if let keyValue = self.value(forKey: stringKey) {
                swiftDictionary[stringKey] = keyValue
            }
        }

        return swiftDictionary
    }
}

private func jsonToDict(text: String) -> [String: Any]? {
    if let data = text.data(using: .utf8) {
        do {
            return try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]
        } catch {
            print(error.localizedDescription)
        }
    }
    return nil
}

private func dictToJson(data: [String: Any]) -> String? {
    guard let jsonData = try? JSONSerialization.data(withJSONObject: data, options: .prettyPrinted) else {
        print("Something is wrong while converting dictionary to JSON data.")
        return nil
    }

    guard let jsonString = String(data: jsonData, encoding: .utf8) else {
        print("Something is wrong while converting JSON data to JSON string.")
        return nil
    }

    return jsonString
}

public func keystoneHttpRequest(
    baseUrl: String,
    endpoint: String,
    apiKey: String,
    requestData: [String: Any],
    handler: @escaping ([String: Any]?) -> Void
) {
    let url = URL(string: "http://\(baseUrl)\(endpoint)")!

    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.setValue(apiKey, forHTTPHeaderField: "x-api-key")
    let requestBody = dictToJson(data: requestData)!.data(using: .utf8)!
    print("Request Body:")
    print(String(data: requestBody, encoding: .utf8)!)
    request.httpBody = requestBody

    let task = URLSession.shared.dataTask(with: request) {(data, _, _) in
        guard let data = data else { return }
        print("Response Body:")
        print(String(data: data, encoding: .utf8)!)
        let parsed = jsonToDict(text: String(data: data, encoding: .utf8)!)
        handler(parsed)
    }

    task.resume()
}

public func rotateKeypairs(
    baseUrl: String,
    apiKey: String,
    handler: @escaping () -> Void
) {
    keystoneHttpRequest(
        baseUrl: baseUrl,
        endpoint: "/keypairs",
        apiKey: apiKey,
        requestData: [:],
        handler: { _ in
            handler()
        }
    )
}

public func getOneTimeKey(
    baseUrl: String,
    apiKey: String,
    authData: String,
    handler: @escaping (OneTimeKey) -> Void
) {
    let request = ["data": authData]

    keystoneHttpRequest(
        baseUrl: baseUrl,
        endpoint: "/onetimekeys",
        apiKey: apiKey,
        requestData: request,
        handler: { response in
            let dict = response!
            handler(
                OneTimeKey(
                    id: String(dict["id"] as! Int),
                    keyMaterialBase64: (dict["publicKey"] as! String?)!
                )
            )
        }
    )
}

public func translatePin(
    baseUrl: String,
    apiKey: String,
    authData: String,
    hostKey: String,
    clientPan: String,
    clientFormat: String,
    hostPan: String,
    hostFormat: String,
    encryptedPinblock: String,
    wrappedZpk: String,
    encryptedBy: String,
    oneTimeKeyId: String,
    handler: @escaping (Pinblock) -> Void
) {
    let message: [String: Any] = [
        "encryptedPinblock": encryptedPinblock,
        "clientPan": clientPan,
        "clientFormat": clientFormat,
        "hostPan": hostPan,
        "hostFormat": hostFormat,
        "encryptedBy": encryptedBy,
        "wrappedZpk": wrappedZpk,
        "authData": authData
    ]

    let urlEncodedHostKeyName = hostKey.addingPercentEncoding(withAllowedCharacters: .urlHostAllowed)!
    keystoneHttpRequest(
        baseUrl: baseUrl,
        endpoint: "/onetimekeys/\(oneTimeKeyId)/pinblock/\(urlEncodedHostKeyName)",
        apiKey: apiKey,
        requestData: message,
        handler: {response in
            let dict = response!
            handler(
                Pinblock(
                encryptedPinblock: (dict["data"] as! String?)!,
                pan: (dict["pan"] as! String?)!,
                format: Pinblock.PinblockFormat(rawValue: (dict["format"] as! String?)!)!
            ))
        }
    )

}

public func translateData(
    baseUrl: String,
    apiKey: String,
    authData: String,
    hostKey: String,
    encryptedData: WrappedData,
    direction: String,
    handler: @escaping (EncryptedData) -> Void
) {
    let data = encryptedData.getEncryptedData()
    let message: [String: Any] = [
        "encryptedData": [
            "cipherText": data.getCipherText(),
            "mode": data.getMode().rawValue,
            "alg": data.getAlg(),
            "iv": data.getIv()
        ],
        "clientKey": [
            "wrappedKey": encryptedData.getClientKey().getWrappedKey(),
            "alg": encryptedData.getClientKey().getAlg()
        ],
        "authData": authData,
        "direction": direction
    ]

    let urlEncodedHostKeyName = hostKey.addingPercentEncoding(withAllowedCharacters: .urlHostAllowed)!
    keystoneHttpRequest(
        baseUrl: baseUrl,
        endpoint: "/onetimekeys/\(encryptedData.getWrappingKeyId())/data/\(urlEncodedHostKeyName)",
        apiKey: apiKey,
        requestData: message,
        handler: {response in
            let dict = response!
            handler(
                EncryptedData(
                cipherText: (dict["cipherText"] as? String)!,
                iv: dict["iv"] as! String?,
                mode: BlockCipherMode(rawValue: (dict["mode"] as! String?)!)!,
                alg: (dict["alg"] as! String?)!
            ))
        }
    )

}
