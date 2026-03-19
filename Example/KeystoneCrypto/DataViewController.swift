//
//  ViewController.swift
//  KeystoneCrypto
//
//  Created by kcekron@gmail.com on 01/25/2019.
//  Copyright (c) 2019 kcekron@gmail.com. All rights reserved.
//

import UIKit
import KeystoneCrypto

class DataViewController: UIViewController {

    @IBOutlet weak var data: UITextField!
    @IBOutlet weak var apiKey: UITextField!
    @IBOutlet weak var baseUrl: UITextField!
    @IBOutlet weak var hostKeyName: UITextField!
    @IBOutlet weak var outputLabel: UILabel!

    @IBAction func rotateKeypairsHandler(sender: UIButton) {
        rotateKeypairs(
            baseUrl: baseUrl.text!,
            apiKey: apiKey.text!,
            handler: {
                print("Done keypairs")
            }
        )
    }

    @IBAction func doStuff(sender: UIButton) {
        let kcrypto = KeystoneCrypto()

        getOneTimeKey(
            baseUrl: baseUrl.text!,
            apiKey: apiKey.text!,
            authData: "random_session_id",
            handler: { [self] otk in
                do {
                    let lk = try kcrypto.GenerateLocalKey(otk: otk)
                    let encryptedData = try kcrypto.EncryptData(data: data.text!, key: lk, mode: BlockCipherMode.CBC)

                    translateData(
                        baseUrl: baseUrl.text!,
                        apiKey: apiKey.text!,
                        authData: "random_session_id",
                        hostKey: hostKeyName.text!,
                        encryptedData: encryptedData,
                        direction: "ToHostKey",
                        handler: { [self] encryptedData in
                            getOneTimeKey(
                                baseUrl: baseUrl.text!,
                                apiKey: apiKey.text!,
                                authData: "random_session_id_2",
                                handler: { [self] otk in
                                    do {
                                        let lk = try kcrypto.GenerateLocalKey(otk: otk)
                                        let wrappedData =
                                        translateData(
                                            baseUrl: baseUrl.text!,
                                            apiKey: apiKey.text!,
                                            authData: "random_session_id_2",
                                            hostKey: hostKeyName.text!,
                                            encryptedData: WrappedData(encryptedData: encryptedData, localKey: lk),
                                            direction: "ToClientKey",
                                            handler: { [self] encryptedData in
                                                do {
                                                    let decryptedData = try kcrypto.DecryptData(data: encryptedData, key: lk)
                                                    DispatchQueue.main.async {
                                                        outputLabel.text = "Data from host \(decryptedData)"
                                                    }
                                                } catch {
                                                    print(error.localizedDescription)
                                                }
                                            }
                                        )
                                    } catch {
                                        print(error.localizedDescription)
                                    }
                                }
                            )

                        }
                    )
                } catch let e {
                    print(e)
                    // Do noting
                }
            }
        )
    }

}

//
//  DataViewController.swift
//  KeystoneCrypto_Example
//
//  Created by Damien on 2024/11/12.
//  Copyright © 2024 CocoaPods. All rights reserved.
//

import Foundation
