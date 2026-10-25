# acryptohashnet SHA3-256 subset

Source: https://github.com/AndreyRusyaev/acryptohashnet
Revision: 6629a581701cd3af14f55f542b0851a77b72af26
Copyright: Andrey Rusyaev. License: LGPL-2.1; the upstream LICENSE is included.

Includes Sha3_256, Keccak, BlockHashAlgorithm, PaddingType, LittleEndian and BitOperations.
The namespace was moved into LibProsperoPkg.ThirdParty.ACryptoHashNet and public helper types
were made internal. Nullable analysis is disabled for these upstream sources. The algorithm
and buffering implementation are unchanged. This subset provides the managed fallback when
System.Security.Cryptography.SHA3_256 is unavailable.
