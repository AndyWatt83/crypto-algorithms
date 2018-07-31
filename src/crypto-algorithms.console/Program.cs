using System;
using crypto_algorithms;

namespace crypto_algorithms.console
{
    class Program
    {
        static void Main(string[] args)
        {
            string input = "password";
            CustomSHA256 SHA = new CustomSHA256();
            Console.WriteLine(SHA.Hash(input));
        }
    }
}
