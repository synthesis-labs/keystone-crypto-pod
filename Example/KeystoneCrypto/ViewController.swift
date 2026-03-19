//
//  ViewController.swift
//  KeystoneCrypto
//
//  Created by kcekron@gmail.com on 01/25/2019.
//  Copyright (c) 2019 kcekron@gmail.com. All rights reserved.
//

import UIKit
import KeystoneCrypto

class ViewController: UIViewController {

    @IBOutlet weak var pin: UITextField!
    @IBOutlet weak var clientPan: UITextField!
    @IBOutlet weak var hostPan: UITextField!
    @IBOutlet weak var clientFormat: UITextField!
    @IBOutlet weak var hostFormat: UITextField!
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
                    let lk = try kcrypto.GenerateLocalKey(otk: otk, keyType: LocalKey.KeyType.AES )
                    let pinblock = try kcrypto.EncryptPin(pin: pin.text!, key: lk, pan: clientPan.text!)

                    translatePin(
                        baseUrl: baseUrl.text!,
                        apiKey: apiKey.text!,
                        authData: "random_session_id",
                        hostKey: hostKeyName.text!,
                        clientPan: pinblock.getPAN()!,
                        clientFormat: clientFormat.text!,
                        hostPan: hostPan.text!,
                        hostFormat: hostFormat.text!,
                        encryptedPinblock: pinblock.getEncryptedPinblock(),
                        wrappedZpk: lk.getEncryptedKeyMaterial(),
                        encryptedBy: "Client",
                        oneTimeKeyId: lk.getWrappingKey().getId(),
                        handler: { [self] pinblock in
                            getOneTimeKey(
                                baseUrl: baseUrl.text!,
                                apiKey: apiKey.text!,
                                authData: "random_session_id_2",
                                handler: { [self] otk in
                                    do {
                                        let lk = try kcrypto.GenerateLocalKey(otk: otk, keyType: LocalKey.KeyType.AES)
                                        translatePin(
                                            baseUrl: baseUrl.text!,
                                            apiKey: apiKey.text!,
                                            authData: "random_session_id_2",
                                            hostKey: hostKeyName.text!,
                                            clientPan: clientPan.text!,
                                            clientFormat: clientFormat.text!,
                                            hostPan: pinblock.getPAN()!,
                                            hostFormat: pinblock.getFormat().rawValue,
                                            encryptedPinblock: pinblock.getEncryptedPinblock(),
                                            wrappedZpk: lk.getEncryptedKeyMaterial(),
                                            encryptedBy: "Host",
                                            oneTimeKeyId: lk.getWrappingKey().getId(),
                                            handler: { [self] pinblock in
                                                do {
                                                    let decryptedPin = try kcrypto.DecryptPinblock(pinblock: pinblock, key: lk)
                                                    DispatchQueue.main.async {
                                                        outputLabel.text = "Pin from host: \(decryptedPin) "
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
