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

import Foundation

/// Mapping of user tier to allowed usecase names. Server config usecase names should match these when using tier
/// gating.
enum TierUsecases {
    /// Usecase name for identity (caller ID) data.
    static let identity = "identity"
    /// Usecase name for block (blocking) data.
    static let block = "block"

    private static let allowlist: [UserTier: Set<String>] = [
        .tier1: [identity, block],
        .tier2: [identity],
        .tier3: [block],
        .tier4: [],
    ]

    private static let allGatedUsecases: Set<String> = Set(allowlist.values.flatMap(\.self))

    /// Returns whether the usecase is allowed for the given tier.
    /// Usecases not listed in any tier's allowlist are implicitly allowed for all tiers.
    static func isAllowed(_ usecase: String, for tier: UserTier) -> Bool {
        guard allGatedUsecases.contains(usecase) else {
            return true
        }
        return allowlist[tier]?.contains(usecase) ?? false
    }
}
