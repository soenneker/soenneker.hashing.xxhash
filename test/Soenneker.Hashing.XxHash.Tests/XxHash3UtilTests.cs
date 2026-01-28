using System;
using System.IO.Hashing;
using System.Text;
using AwesomeAssertions;
using Xunit;

namespace Soenneker.Hashing.XxHash.Tests;

public sealed class XxHash3UtilTests
{
    public XxHash3UtilTests(ITestOutputHelper output)
    {

    }

    [Fact]
    public void Hash_matches_system_xxhash3()
    {
        const string value = "hello world";

        ulong expected = XxHash3.HashToUInt64(Encoding.UTF8.GetBytes(value));
        string expectedHex = expected.ToString("x16");

        string actual = XxHash3Util.Hash(value);

        actual.Should().Be(expectedHex);
    }

    [Fact]
    public void Verify_returns_true_for_matching_hash()
    {
        const string value = "verify me";
        string hash = XxHash3Util.Hash(value);

        bool result = XxHash3Util.Verify(value, hash);

        result.Should().BeTrue();
    }

    [Fact]
    public void Verify_returns_false_for_mismatch()
    {
        const string value = "verify me";
        const string other = "different value";
        string hash = XxHash3Util.Hash(other);

        bool result = XxHash3Util.Verify(value, hash);

        result.Should().BeFalse();
    }

    [Fact]
    public void Hash_throws_on_null()
    {
        Action action = () => XxHash3Util.Hash(null!);
        action.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Verify_throws_on_null_inputs()
    {
        Action nullValue = () => XxHash3Util.Verify(null!, "abc");
        Action nullHash = () => XxHash3Util.Verify("abc", null!);

        nullValue.Should().Throw<ArgumentNullException>();
        nullHash.Should().Throw<ArgumentNullException>();
    }
}
