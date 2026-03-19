public class WrappedData {
    private var encryptedData: EncryptedData
    private var clientKey: WrappedClientKey
    private var wrappingKeyId: String

    public init(encryptedData: EncryptedData, clientKey: WrappedClientKey, wrappingKeyId: String) {
        self.encryptedData = encryptedData
        self.clientKey = clientKey
        self.wrappingKeyId = wrappingKeyId
    }

    public init(encryptedData: EncryptedData, localKey: LocalKey) {
        self.encryptedData = encryptedData
        self.clientKey = localKey.getWrappedClientKey()
        self.wrappingKeyId = localKey.getWrappingKey().getId()
    }

    public func getEncryptedData() -> EncryptedData {
        return encryptedData
    }

    public func getClientKey() -> WrappedClientKey {
        return clientKey
    }

    public func getWrappingKeyId() -> String {
        return wrappingKeyId
    }
}
