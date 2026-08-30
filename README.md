[![](https://img.shields.io/nuget/v/soenneker.hashing.xxhash.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.hashing.xxhash/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.hashing.xxhash/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.hashing.xxhash/actions/workflows/publish-package.yml)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.hashing.xxhash/build-and-test.yml?style=for-the-badge&label=build)](https://github.com/soenneker/soenneker.hashing.xxhash/actions/workflows/build-and-test.yml)
[![](https://img.shields.io/nuget/dt/soenneker.hashing.xxhash.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.hashing.xxhash/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.hashing.xxhash/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.hashing.xxhash/actions/workflows/codeql.yml)

# Soenneker.Hashing.XxHash

Fast XXH3 64-bit hashing for byte spans and UTF-8 text, with integer and canonical 16-character lowercase hexadecimal outputs.

XXH3 is non-cryptographic. Use it for hash-table keys, cache keys, partition selection, deduplication hints, and accidental-corruption checks. Do not use it for passwords, signatures, authentication tokens, or adversarial integrity checks.

## Installation

```bash
dotnet add package Soenneker.Hashing.XxHash
```

## Hash UTF-8 text

```csharp
using Soenneker.Hashing.XxHash;

string hex = XxHash3Util.Hash("customer:42");
// 16 lowercase hex characters

ulong numeric = XxHash3Util.HashToUInt64("customer:42");
```

String and character-span overloads encode text as UTF-8 before hashing, so the same Unicode text produces the same result across processes.

## Hash bytes or use a seed

```csharp
ReadOnlySpan<byte> payload = ...;

ulong standard = XxHash3Util.HashToUInt64(payload);
ulong partitioned = XxHash3Util.HashUtf8ToUInt64(payload, seed: 17);
```

A seed produces a different deterministic hash family; it is not a secret key and does not make XXH3 cryptographically secure.

## Compare a stored text hash

```csharp
string expected = XxHash3Util.Hash(value);
bool matches = XxHash3Util.Verify(value, expected);
```

`Verify()` accepts exactly 16 hexadecimal characters and returns `false` for malformed values or a mismatch. This comparison is a convenience check, not constant-time authentication.

Character inputs up to the internal threshold are UTF-8 encoded on the stack; larger inputs use a pooled byte array. Byte-span hashing itself does not allocate. Null string overload arguments throw `ArgumentNullException`; span overloads naturally support empty input.
