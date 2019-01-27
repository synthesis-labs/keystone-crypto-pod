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
            let otkBase64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0WuhgKiPvp1hW6pnPUO6BrQO7z6xhczt21qqXnGLoH/kleYNMBusoOD1hR23SUBm+CIC/yBrQ4Y5CV+PHaFL+Uk963uI4Fuuh4zmkFksCXbaZDYLwaxXCxzekCh61YiPPQzHaqPf7alzaxVMnycIQlgNipA8/8FqmILss8ikRwlV4BuUnZmLmYjFIk+/4p5NPYE+RvW3pOCuYTPLJMquHK/0vofdfC5Yw3yDaEOHHx4rFrFjmuni1th4r/bHypkesFCshNyjhw6AhaUoDsLAWzXWmA/2IChs3u/kzqfFEn2Sy427+6zKZPoW6R7nA1Ho9bcMIaZYBYBXf6pznD7WxwIDAQAB"
            
            let otk = try OneTimeKey(id: otkId, keyMaterialBase64: otkBase64)
            
            // 2) Generate local key using retrieved one time key
            let lk = try kcrypto.GenerateLocalKey(otk: otk)
            
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
