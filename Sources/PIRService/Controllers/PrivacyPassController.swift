// Copyright 2024 Apple Inc. and the Swift Homomorphic Encryption project authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import Foundation
import HTTPTypes
import Hummingbird
import PrivacyPass

struct PrivacyPassController<UserAuthenticator: UserTokenAuthenticator> {
    let state: PrivacyPassState<UserAuthenticator>

    func addRoutes(to group: RouterGroup<AppContext>) {
        group.get("/.well-known/private-token-issuer-directory", use: tokenIssuerDirectory)
        group.get("/token-key-for-user-token", use: tokenKeyForUserToken)
        group.post("/issue", use: issueToken)
    }

    func authenticateUserToken(request: Request) async throws -> UserTier {
        guard let userToken = request.headers.bearerToken,
              let userTier = try await state.userAuthenticator.authenticate(userToken: userToken)
        else {
            throw HTTPError(.unauthorized, message: "User token is unauthorized")
        }
        return userTier
    }

    @Sendable
    func tokenIssuerDirectory(request: Request, context _: AppContext) async throws -> TokenIssuerDirectory {
        let tokenKeys = try await state.issuers.values.map(\.privateKey.publicKey).map { publicKey in
            let spki = try publicKey.spki()
            return TokenIssuerDirectory.TokenKey(
                tokenType: PrivacyPass.TokenTypeBlindRSA,
                tokenKeyBase64Url: spki.base64URLEncodedString(),
                notBefore: nil)
        }
        let issuerRequestUri = Self.absoluteIssuerRequestURI(from: request)
        return TokenIssuerDirectory(issuerRequestUri: issuerRequestUri, tokenKeys: tokenKeys)
    }

    /// Builds an absolute URL for the token issuer so clients (e.g. iOS) can fetch tokens without resolving a relative URI.
    /// RFC 9578 allows "issuer-request-uri" to be absolute or relative; returning an absolute URL avoids error 1100
    /// ("failed to fetch token") when the client does not resolve a relative "/issue" correctly.
    private static func absoluteIssuerRequestURI(from request: Request) -> URL {
        guard let host = request.headers[.host] else {
            // swiftlint:disable:next force_unwrapping
            return URL(string: "/issue")!
        }
        let scheme = request.headers[.xForwardedProto] ?? "https"
        // Ensure path is single /issue (no double slash); host may or may not include port
        guard let url = URL(string: "\(scheme)://\(host)/issue") else {
            // swiftlint:disable:next force_unwrapping
            return URL(string: "/issue")!
        }
        return url
    }

    @Sendable
    func tokenKeyForUserToken(request: Request, context _: AppContext) async throws -> PrivacyPass.PublicKey {
        let userTier = try await authenticateUserToken(request: request)
        guard let issuer = await state.issuers[userTier] else {
            throw HTTPError(.internalServerError, message: "Could not find issuer for tier \(userTier)")
        }
        return issuer.publicKey
    }

    @Sendable
    func issueToken(request: Request, context _: AppContext) async throws -> PrivacyPass.TokenResponse {
        let userTier = try await authenticateUserToken(request: request)
        // decode tokenRequest
        var tokenRequestByteBuffer = try await request.body.collect(upTo: PrivacyPass.TokenRequest.sizeInBytes)
        guard let tokenRequestBytes = tokenRequestByteBuffer.readBytes(length: PrivacyPass.TokenRequest.sizeInBytes)
        else {
            throw PrivacyPass.PrivacyPassError(code: .invalidTokenRequestSize)
        }
        let tokenRequest = try PrivacyPass.TokenRequest(from: tokenRequestBytes)

        guard let issuer = await state.issuers[userTier] else {
            throw HTTPError(.internalServerError, message: "Could not find issuer for tier \(userTier)")
        }

        return try issuer.issue(request: tokenRequest)
    }
}

private extension HTTPField.Name {
    // swiftlint:disable:next force_unwrapping
    static var host: Self { Self("Host")! }
    // swiftlint:disable:next force_unwrapping
    static var xForwardedProto: Self { Self("X-Forwarded-Proto")! }
}
