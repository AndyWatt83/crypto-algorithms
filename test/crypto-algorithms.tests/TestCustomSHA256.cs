using System;
using Xunit;
using crypto_algorithms;

namespace crypto_algorithms.tests
{
    public class TestCustomSHA256
    {
        [Fact]
        public void TestAString()
        {
            //Generated from: https://passwordsgenerator.net/sha256-hash-generator/
            string expected = "5E884898DA28047151D0E56F8DC6292773603D0D6AABBDD62A11EF721D1542D8";
            string input = "password";

            CustomSHA256 SHA = new CustomSHA256();
            string actual = SHA.Hash(input);

            Assert.Equal(expected, actual);
        }
    }
}
