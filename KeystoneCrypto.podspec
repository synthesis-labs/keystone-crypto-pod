Pod::Spec.new do |s|
    s.name             = 'KeystoneCrypto'
    s.version          = '1.0.1'
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
  s.source           = { :git => 'https://github.com/synthesis-labs/keystone-crypto-pod.git', :tag => s.version.to_s }

  s.ios.deployment_target = '10.0'
  s.swift_version         = '4.0'
  s.platform              = :ios, '10.0'

  s.source_files = 'KeystoneCrypto/Classes/**/*.{swift}'
  
  s.dependency 'IDZSwiftCommonCrypto', '~> 0.9.1'
  s.dependency 'SwiftyRSA', '~> 1.5.0'
  
end
