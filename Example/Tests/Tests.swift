import XCTest
import KeystoneCrypto

class Tests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testExample() {
        do {
            let kcrypto = KeystoneCrypto()
            
            // 1) This ID and public key base 64 must be fetched from the backend server. This otk should be linked to the calling user
            let otkId = "12345"
            let otkBase64 = "MIIBCgKCAQEAtC42LOM4H4u6o0VG5iHBfoZGal6ZArOehNJuZ36gOcVegm74BvuCGHjrkfm3xshye4HWJuwa0Q8bPMGdBM31OivAoR0fQDyoa1A2gy1Fz2HiEMNTgoCg3valp0aFhGksTEXxahe9VnPODQmkNmzWrs0U7ZHj2fsopxLa2AgzEpY9cPZ36A1uRHnPUgqk6UBxs3rRD23oxNQsAtC8JC8aLTjSF9yCRw3bjbjZTmiEAAFSiXKCLLzoTaSgrk+xwwur2GE7PKG4rpM7NxuoUh4nf+umX+dpoyU+QM6bAyMR8CVj62Y2orXKjeXTsSxe/EgyXIG5l/JvOcNTNLx9XfWNHQIDAQAB"
            
            let otk = try OneTimeKey(id: otkId, keyMaterialBase64: otkBase64)
            
            // 2) Generate local key using retrieved one time key
            let lk = try kcrypto.GenerateLocalKey(otk: otk)
            
            // Usually, only one of steps 3 and 4 is performed. Either the user's PIN is captured and transmitted, or a PIN is delivered from the backend server and decrypted on the local client
            
            // 3) Encrypt user PIN with the generated localkey
            let userPin = "1234"
            let pinblock = try kcrypto.EncryptPin(pin: userPin, key: lk)
            
            // 4) Decrypt PINBlock using local key
            let decryptedPin = try kcrypto.DecryptPinblock(pinblock: pinblock, key: lk)

            print (lk.getEncryptedKeyMaterial())
            print (lk.getKCV())
            
            XCTAssert(decryptedPin == userPin, "Pass")
            
        } catch let err {
            print(err)
        }
        // This is an example of a functional test case.
        
    }

    func testAESExample() {
        do {
            let kcrypto = KeystoneCrypto()
            
            // 1) This ID and public key base 64 must be fetched from the backend server. This otk should be linked to the calling user
            let otkId = "12345"
            let otkBase64 = "MIIBCgKCAQEAuZRZyULptjTEbioVpUGOMoS38jbr7rQ0lXpJMG2y68KhHRI9EDTybwpz0tcmSCLK5XLTB89r7xzLN9jg8zodU/0pBUQQwbqqjfuXPZEFW7pmM7YjgiBMXllkvcsIZFkSd10xMNYXMJQQEcIxrKnISCzlGPYdpFU4sRzxynWcnqEqz+vHRgNkSD8di910tZY/7plvuSMIUilsK5hGhrrrc06hDVABXOdrtzIvZM8GEXa7cjDDCOmKof7SKOmBPMmm6j1x4iMi72Zzrvy58lQUAb3EGyOHihCJ8UNRkdBWjKNfy8JmVuh0ExANkf9Kk+/fGEWdUx82xnBGoTjidGSnuQIDAQAB"
            
            let otk = try OneTimeKey(id: otkId, keyMaterialBase64: otkBase64)
            
            // 2) Generate local key using retrieved one time key
            let lk = try kcrypto.GenerateLocalKey(otk: otk, keyType: LocalKey.KeyType.AES)
            
            // Usually, only one of steps 3 and 4 is performed. Either the user's PIN is captured and transmitted, or a PIN is delivered from the backend server and decrypted on the local client
            
            // 3) Encrypt user PIN with the generated localkey
            let userPin = "1234"
            let pinblock = try kcrypto.EncryptPin(pin: userPin, key: lk)
            
            // 4) Decrypt PINBlock using local key
            let decryptedPin = try kcrypto.DecryptPinblock(pinblock: pinblock, key: lk)
            
            XCTAssert(decryptedPin == userPin, "Pass")
            
        } catch let err {
            print(err)
        }
        // This is an example of a functional test case.
        
    }

    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measure() {
            // Put the code you want to measure the time of here.
        }
    }
    
}
