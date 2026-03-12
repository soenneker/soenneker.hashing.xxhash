using Soenneker.Extensions.Spans.Readonly.Chars;
using System;
using System.Buffers;
using System.Diagnostics.Contracts;
using System.IO.Hashing;
using System.Runtime.CompilerServices;
using System.Text;

namespace Soenneker.Hashing.XxHash;

/// <summary>
/// High-performance XXH3 (64-bit) hashing utilities with UTF-8 string adapters,
/// stackalloc / pooling optimizations, and allocation-free hex formatting.
/// </summary>
public static class XxHash3Util
{
    /// <summary>
    /// Maximum UTF-8 byte count that will be stackallocated before falling back to pooling.
    /// </summary>
    private const int _stackallocByteThreshold = 256;

    private static readonly Encoding _utf8 = Encoding.UTF8;

    // ------------------------------------------------------------------
    // Convenience: string / char hashing with hex output
    // ------------------------------------------------------------------

    /// <summary>
    /// Computes a lowercase 16-character hexadecimal XXH3 hash of the provided string.
    /// </summary>
    /// <param name="value">The input string to hash.</param>
    /// <returns>A 16-character lowercase hexadecimal hash.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="value"/> is null.</exception>
    [Pure]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static string Hash(string value)
    {
        if (value is null)
            throw new ArgumentNullException(nameof(value));

        return Hash(value.AsSpan());
    }

    /// <summary>
    /// Computes a lowercase 16-character hexadecimal XXH3 hash of the provided character span.
    /// UTF-8 encoding is applied internally.
    /// </summary>
    /// <param name="value">The input characters to hash.</param>
    /// <returns>A 16-character lowercase hexadecimal hash.</returns>
    [Pure]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static string Hash(ReadOnlySpan<char> value)
    {
        ulong hash = HashToUInt64(value);

        // Always produces 16 lowercase hex chars (big-endian nibble order)
        return string.Create(16, hash, static (span, h) =>
        {
            for (var i = 15; i >= 0; i--)
            {
                var nibble = (int)(h & 0xFu);
                span[i] = (char)(nibble < 10 ? '0' + nibble : 'a' + (nibble - 10));
                h >>= 4;
            }
        });
    }

    /// <summary>
    /// Computes a 64-bit hash value for the specified UTF-8 encoded byte sequence.
    /// </summary>
    /// <remarks>The hash result is deterministic for the same input and seed. Providing a nonzero seed allows
    /// for generating different hash values for the same input, which can be useful for scenarios such as randomized
    /// hashing or hash partitioning.</remarks>
    /// <param name="utf8">A read-only span of bytes containing the UTF-8 encoded data to hash.</param>
    /// <param name="seed">An optional seed value to influence the hash computation. Use 0 for the default hash behavior.</param>
    /// <returns>A 64-bit unsigned integer representing the hash of the input data.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong HashUtf8ToUInt64(ReadOnlySpan<byte> utf8, long seed = 0)
    {
        return seed == 0
            ? HashToUInt64(utf8)
            : HashToUInt64(utf8, seed);
    }

    /// <summary>
    /// Computes a 64-bit hash value for the specified sequence of characters, optionally using a custom seed.
    /// </summary>
    /// <remarks>This method encodes the input characters as UTF-8 before computing the hash. Using the same
    /// seed and input will always produce the same hash value. The method is suitable for generating hash codes for
    /// text data where consistent results are required across executions.</remarks>
    /// <param name="chars">The sequence of characters to hash. The characters are interpreted as UTF-8 encoded text.</param>
    /// <param name="seed">An optional seed value to influence the hash computation. If not specified, a default seed is used.</param>
    /// <returns>A 64-bit unsigned integer representing the hash of the input characters.</returns>
    public static ulong HashCharsToUInt64(ReadOnlySpan<char> chars, long seed = 0)
    {
        if (chars.IsEmpty)
            return seed == 0 ? HashToUInt64(ReadOnlySpan<byte>.Empty) : HashToUInt64(ReadOnlySpan<byte>.Empty, seed);

        int byteCount = _utf8.GetByteCount(chars);

        if (byteCount <= _stackallocByteThreshold)
        {
            Span<byte> tmp = stackalloc byte[_stackallocByteThreshold];
            int written = _utf8.GetBytes(chars, tmp);

            ReadOnlySpan<byte> payload = tmp[..written];

            return seed == 0 ? HashToUInt64(payload) : HashToUInt64(payload, seed);
        }

        byte[] rented = ArrayPool<byte>.Shared.Rent(byteCount);

        try
        {
            int written = _utf8.GetBytes(chars, rented);
            var payload = new ReadOnlySpan<byte>(rented, 0, written);

            return seed == 0 ? HashToUInt64(payload) : HashToUInt64(payload, seed);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    /// <summary>
    /// Verifies that the provided string hashes to the expected hexadecimal XXH3 value.
    /// </summary>
    /// <param name="value">The input string to hash.</param>
    /// <param name="expectedHash">A 16-character hexadecimal hash to compare against.</param>
    /// <returns><c>true</c> if the hashes match; otherwise <c>false</c>.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="value"/> or <paramref name="expectedHash"/> is null.
    /// </exception>
    [Pure]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool Verify(string value, string expectedHash)
    {
        if (value is null)
            throw new ArgumentNullException(nameof(value));

        if (expectedHash is null)
            throw new ArgumentNullException(nameof(expectedHash));

        return Verify(value.AsSpan(), expectedHash.AsSpan());
    }

    /// <summary>
    /// Verifies that the provided character span hashes to the expected hexadecimal XXH3 value.
    /// </summary>
    /// <param name="value">The input characters to hash.</param>
    /// <param name="expectedHash">A 16-character hexadecimal hash to compare against.</param>
    /// <returns><c>true</c> if the hashes match; otherwise <c>false</c>.</returns>
    [Pure]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool Verify(ReadOnlySpan<char> value, ReadOnlySpan<char> expectedHash)
    {
        if (!expectedHash.TryParseHexUInt64(out ulong expected))
            return false;

        return HashToUInt64(value) == expected;
    }

    // ------------------------------------------------------------------
    // Core: byte hashing (no encoding, zero allocations)
    // ------------------------------------------------------------------

    /// <summary>
    /// Computes a 64-bit XXH3 hash for the provided byte span.
    /// </summary>
    /// <param name="data">The bytes to hash.</param>
    /// <returns>The computed 64-bit hash.</returns>
    [Pure]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong HashToUInt64(ReadOnlySpan<byte> data) => XxHash3.HashToUInt64(data);

    /// <summary>
    /// Computes a 64-bit XXH3 hash for the provided byte span.
    /// </summary>
    /// <param name="data">The bytes to hash.</param>
    /// <param name="seed"></param>
    /// <returns>The computed 64-bit hash.</returns>
    [Pure]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong HashToUInt64(ReadOnlySpan<byte> data, long seed) => XxHash3.HashToUInt64(data, seed);

    // ------------------------------------------------------------------
    // Adapters: text → UTF-8 → bytes
    // ------------------------------------------------------------------

    /// <summary>
    /// Computes a 64-bit XXH3 hash for the provided string using UTF-8 encoding.
    /// </summary>
    /// <param name="value">The input string to hash.</param>
    /// <returns>The computed 64-bit hash.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="value"/> is null.</exception>
    [Pure]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong HashToUInt64(string value)
    {
        if (value is null)
            throw new ArgumentNullException(nameof(value));

        return HashToUInt64(value.AsSpan());
    }

    /// <summary>
    /// Computes a 64-bit XXH3 hash for the provided character span using UTF-8 encoding.
    /// Uses stackalloc for small inputs and pooled buffers for larger inputs.
    /// </summary>
    /// <param name="value">The input characters to hash.</param>
    /// <returns>The computed 64-bit hash.</returns>
    [Pure]
    public static ulong HashToUInt64(ReadOnlySpan<char> value)
    {
        int byteCount = _utf8.GetByteCount(value);

        if (byteCount <= _stackallocByteThreshold)
        {
            Span<byte> buffer = stackalloc byte[byteCount];
            _utf8.GetBytes(value, buffer);
            return HashToUInt64(buffer);
        }

        byte[] rented = ArrayPool<byte>.Shared.Rent(byteCount);
        try
        {
            Span<byte> span = rented.AsSpan(0, byteCount);
            _utf8.GetBytes(value, span);
            return HashToUInt64(span);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }
}