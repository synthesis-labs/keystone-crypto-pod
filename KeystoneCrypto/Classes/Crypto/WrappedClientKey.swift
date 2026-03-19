public enum OaepHash: String {
    case sha1
    case sha256
}

public class WrappedClientKey {
    private let wrappedKey: String
    private let alg: LocalKey.KeyType
    private let oaepHash: OaepHash

    init(wrappedKey: String, alg: LocalKey.KeyType, oaepHash: OaepHash = OaepHash.sha1) {
        self.wrappedKey = wrappedKey
        self.alg = alg
        self.oaepHash = oaepHash
    }

    public func getWrappedKey() -> String {
        return wrappedKey
    }

    public func getAlg() -> String {
        if alg == LocalKey.KeyType.AES {
            return "AES128"
        } else {
            return "DES3"
        }
    }

    public func getOaepHash() -> String {
        return oaepHash.rawValue
    }

}
