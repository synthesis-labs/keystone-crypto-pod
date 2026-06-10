Pod::Spec.new do |s|
    s.name             = 'KeystoneCrypto'
    s.version = '0.0.0-develop-e40957ad5a3db45a75dfe43a14e1b755afe1b8e9'
    s.summary          = 'Crypto functions to interact with Keystone service'

    s.description      = <<-DESC
    Contains the necessary functions to interact with Keystone including:
    - Generation of local encryption key
    - Encryption of PIN
    - Decryption of PINBlock
                       DESC

  s.homepage         = 'https://github.com/synthesis-labs/keystone-crypto-pod'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'Kieron Ekron' => 'kieron@synthesis.co.za' }
  s.source           = { :git => 'https://github.com/synthesis-labs/keystone-crypto-pod.git', :tag => s.version = '0.0.0-develop-e40957ad5a3db45a75dfe43a14e1b755afe1b8e9' }

  s.ios.deployment_target = '10.0'
  s.swift_version         = '4.0', '5.0'

  s.source_files = 'KeystoneCrypto/Classes/**/*.{swift}'
  
  s.dependency 'IDZSwiftCommonCrypto', '0.13.0'
  
end
