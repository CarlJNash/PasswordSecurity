//
//  ContentView.swift
//  PasswordSecurity
//
//  Created by Carl Nash on 09/05/2023.
//

import SwiftUI

struct ContentView: View {

    let viewModel = ContentViewModel()

    var body: some View {
        VStack {
            Image(systemName: "globe")
                .imageScale(.large)
                .foregroundColor(.accentColor)
            Text("Hello, world!")
        }
        .padding()
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}

import Foundation
import CryptoKit
import CommonCrypto
import Security

class ContentViewModel {

    func hashPassword(_ password: String) -> String? {
        guard let salt = generateSalt() else {
            return nil
        }

        let passwordData = Data(password.utf8)
        let saltData = Data(salt.utf8)
//        var hashData = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
        let hashLength = Int(CC_SHA256_DIGEST_LENGTH)
        var hashBytes = [UInt8](repeating: 0, count: hashLength)

        guard CCKeyDerivationPBKDF(
                CCPBKDFAlgorithm(kCCPBKDF2),
                password,
                passwordData.count,
                salt,
                saltData.count,
                CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                10000, // iterations
                &hashBytes,
                hashLength
        ) == kCCSuccess else {
            return nil
        }

        let hashData = Data(hashBytes)
        let saltString = saltData.base64EncodedString()
        let hashString = hashData.base64EncodedString()
        return "\(saltString):\(hashString)"
    }

    private func generateSalt() -> String? {
        let count = 32
        var bytes = [UInt8](repeating: 0, count: count)

        let result = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        guard result == errSecSuccess else {
            return nil
        }

        return Data(bytes).base64EncodedString()
    }

    func savePasswordToKeychain(password: String) -> Bool {
        let service = "com.example.app"
        let account = "user123"

        guard let passwordData = password.data(using: .utf8) else {
            return false
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: passwordData
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        return status == errSecSuccess
    }

    init() {
        let password = "someCrappyPassword"
        if let hashedPassword = hashPassword(password) {
            print(hashedPassword)
            let saved = savePasswordToKeychain(password: hashedPassword)
            if saved {
                print("saved")
            } else {
                print("not saved")
            }
        } else {
            print("could not hash password")
        }
    }

}
