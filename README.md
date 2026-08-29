[![](https://img.shields.io/nuget/v/soenneker.hashing.xxhash.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.hashing.xxhash/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.hashing.xxhash/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.hashing.xxhash/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.hashing.xxhash.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.hashing.xxhash/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.hashing.xxhash/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.hashing.xxhash/actions/workflows/codeql.yml)

# Soenneker.Hashing.XxHash

High-performance XXH3 (64-bit) hashing utilities with UTF-8 string adapters, stackalloc / pooling optimizations, and allocation-free hex formatting.

## Install

```bash
dotnet add package Soenneker.Hashing.XxHash
```

## Quick start

```csharp
using Soenneker.Hashing.XxHash;

var result = XxHash3Util.Hash("value");
```

Computes a lowercase 16-character hexadecimal XXH3 hash of the provided string.

## What you get

- `XxHash3Util` — High-performance XXH3 (64-bit) hashing utilities with UTF-8 string adapters, stackalloc / pooling optimizations, and allocation-free hex formatting.

## API at a glance

| API | What it does | Result / important behavior |
| --- | --- | --- |
| `XxHash3Util.Hash(value)` | Computes a lowercase 16-character hexadecimal XXH3 hash of the provided string. | A 16-character lowercase hexadecimal hash. |
| `XxHash3Util.Verify(value, expectedHash)` | Verifies that the provided string hashes to the expected hexadecimal XXH3 value. | `true` if the hashes match; otherwise `false`. |

## Important behavior

- `XxHash3Util.Hash(value)`: `value` is null.
- `XxHash3Util.HashUtf8ToUInt64(utf8, seed)`: The hash result is deterministic for the same input and seed. Providing a nonzero seed allows for generating different hash values for the same input, which can be useful for scenarios such as randomized hashing or hash partitioning.
- `XxHash3Util.HashCharsToUInt64(chars, seed)`: This method encodes the input characters as UTF-8 before computing the hash. Using the same seed and input will always produce the same hash value. The method is suitable for generating hash codes for text data where consistent results are required across executions.
- `XxHash3Util.Verify(value, expectedHash)`: `value` or `expectedHash` is null.
- `XxHash3Util.HashToUInt64(value)`: `value` is null.
