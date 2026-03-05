// Copyright 2024-2025 Apple Inc. and the Swift Homomorphic Encryption project authors
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

import Logging

actor UserAuthenticator: UserTokenAuthenticator {
    var allowList: [String: UserTier]
    var allowAnyToken: Bool
    let logger: Logger

    init(logger: Logger) {
        self.allowList = [:]
        self.allowAnyToken = false
        self.logger = logger
    }

    func add(token: String, tier: UserTier) {
        allowList[token] = tier
    }

    func authenticate(userToken: String) async throws -> UserTier? {
        if allowAnyToken {
            logger.info("allowAnyToken: accepting user token as tier1")
            return .tier1
        }
        return allowList[userToken]
    }

    func update(allowList: [String: UserTier], allowAnyToken: Bool) {
        self.allowList = allowList
        self.allowAnyToken = allowAnyToken
    }
}
