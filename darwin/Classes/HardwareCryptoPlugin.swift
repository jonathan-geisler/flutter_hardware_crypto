#if os(iOS)
import Flutter
import UIKit

func messenger(from registrar: FlutterPluginRegistrar) -> FlutterBinaryMessenger {
    registrar.messenger()
}
#elseif os(macOS)
import Cocoa
import FlutterMacOS

func messenger(from registrar: FlutterPluginRegistrar) -> FlutterBinaryMessenger {
    registrar.messenger
}
#else
    #error("Unsupported platform.")
#endif

public class HardwareCryptoPlugin: NSObject, FlutterPlugin {
    public static func register(with registrar: FlutterPluginRegistrar) {
        let api = HardwareCryptoImplementation()
        HardwareCryptoApiSetup.setUp(binaryMessenger: messenger(from: registrar), api: api)
    }
}

private class HardwareCryptoImplementation: HardwareCryptoApi {

    private static let keychainCommonParameters = [
        kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
        kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits: 256,
        kSecUseDataProtectionKeychain: true,
    ] as [String: Any]

    #if targetEnvironment(simulator)
    private static let keychainCreationParameters = [
        kSecPrivateKeyAttrs: [
            kSecAttrAccessControl: SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                [.privateKeyUsage],
                nil
            )!,
            kSecAttrIsPermanent: true,
        ] as [String: Any],
    ].merging(keychainCommonParameters) { (current, _) in current }
    #else
    private static let keychainCreationParameters = [
        kSecPrivateKeyAttrs: [
            kSecAttrAccessControl: SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.biometryAny, .privateKeyUsage],
                nil
            )!,
            kSecAttrIsPermanent: true,
        ] as [String: Any],
    ].merging(keychainCommonParameters) { (current, _) in current }
    #endif

    private static let keychainOtherParameters = [
        kSecClass: kSecClassKey,
        kSecReturnRef: true,
    ].merging(keychainCommonParameters) { (current, _) in current }

    private func getPrivateKey(alias: String) -> Result<SecKey, Error> {
        var parameters = Self.keychainOtherParameters
        parameters[kSecAttrApplicationLabel] = alias

        var queryResult: CFTypeRef?
        let status = SecItemCopyMatching(parameters as CFDictionary, &queryResult)
        guard status == errSecSuccess, let queryResult, CFGetTypeID(queryResult) == SecKeyGetTypeID() else {
            return .failure(NSError(domain: NSOSStatusErrorDomain, code: Int(status)))
        }

        return .success(queryResult as! SecKey)
    }

    func isSupported() throws -> Bool {
        return true
    }
    
    func generateKeyPair(alias: String, completion: @escaping (Result<Bool, Error>) -> Void) {
        var parameters = Self.keychainCreationParameters
        parameters[kSecAttrApplicationLabel] = alias

        var error: Unmanaged<CFError>?
        let key = SecKeyCreateRandomKey(parameters as CFDictionary, &error)
        if key != nil {
            completion(.success(true))
            return
        }

        guard let error else {
            completion(.success(false))
            return
        }

        let errorValue = error.takeRetainedValue()
        // Consider duplicate key (ie. it has already been configured) a success case.
        completion(.success(OSStatus(CFErrorGetCode(errorValue)) == errSecDuplicateItem))
    }

    func deleteKeyPair(alias: String, completion: @escaping (Result<Bool, Error>) -> Void) {
        var parameters = Self.keychainOtherParameters
        parameters[kSecAttrApplicationLabel] = alias
        let status = SecItemDelete(parameters as CFDictionary)
        completion(.success(status == errSecSuccess))
    }

    func sign(alias: String, data: FlutterStandardTypedData, completion: @escaping (Result<FlutterStandardTypedData, Error>) -> Void) {
        let result = getPrivateKey(alias: alias)
        let privateKey: SecKey
        switch result {
        case let .failure(error):
            completion(.failure(error))
            return

        case let .success(privKey):
            privateKey = privKey
        }

        var error: Unmanaged<CFError>?
        let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            data.data as CFData,
            &error
        )
        if let signature {
            completion(.success(.init(bytes: signature as Data)))
            return
        }

        guard let error else {
            completion(.failure(NSError(domain: NSOSStatusErrorDomain, code: Int(errSecCoreFoundationUnknown))))
            return
        }

        completion(.failure(error.takeRetainedValue()))
    }

}
