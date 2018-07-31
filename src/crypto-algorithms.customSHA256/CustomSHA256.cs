using System;
using System.Text;

namespace crypto_algorithms
{
    public class CustomSHA256
    {
        private string _message;
        private byte[] _messagebytes;
        int l;
        int numblocks;
        uint[,] M;
        uint[] K;
        uint[] H;

        public CustomSHA256()
        {
            K = SHAConstants.SHA256Constants;
            H = SHAConstants.InitialHashValues;
        }

        // SHA can encode any byte array, not just strings.
        public string  Hash(String message)
        {
            _message = message;

            this.TransformToByteArray(); //Transform the string message to a byte array

            this.PadMessage(); //Pad the message to the required input specification for input to the hash algorithm

           return  this.HashAlgorithm(); //Run the hash algorithm.
            //Console.WriteLine("{0:X}-{1:X}-{2:X}-{3:X}-{4:X}-{5:X}-{6:X}-{7:X}", H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]);
        }

        private void TransformToByteArray()
        {
            _messagebytes = Encoding.ASCII.GetBytes(_message);
            l = _messagebytes.Length;
        }

        private void PadMessage()
        {
            /* Create array of bytes with a length that is a multiple of 4
             * to house the original message + the extra byte.
             */
            int requiredLength = (int)(Math.Ceiling((l + 1) / 4.0) * 4.0);
            byte[] BYTE_array = new byte[requiredLength];
            Array.Copy(_messagebytes, BYTE_array, l);
            BYTE_array[l] = 0x80;

            /* Process the byte array into an array of 32 bit words (uints)
             * This sections requires attention
             */
            uint[] UINT_array = new uint[(int)(requiredLength / 4)];
            byte[] temp = new byte[4];
            int count = 0;
            for (int i = 0; i < BYTE_array.Length ; i++)
            {
                temp[count] = BYTE_array[i];
                if(count == 3)
                {
                    if (BitConverter.IsLittleEndian)
                    {
                        Array.Reverse(temp);
                    }
                    UINT_array[i/4] = BitConverter.ToUInt32(temp, 0);
                    count = -1;
                }
                count++;
            }

            /* Now need to convert the byte array into a 64xn
             * 2d array of uints forming the padded message
             */
            numblocks = ((int)(Math.Truncate((UINT_array.Length + 2) / 16.0)) + 1);

            M = new uint[16, numblocks];
            for (int j = 0; j < (numblocks); j++)
            {
                for (int i = 0; i < 16; i++)
                {

                    if ((16 * j) + i < UINT_array.Length)
                    {
                        M[i, j] = UINT_array[(16 * j) + i];
                    }
                    else if (i < 14) { M[i, j] = 0; }
                    else { } //do nothing - placeholder for the length information
                }
                Console.WriteLine();
            }

            // The last 64 bytes (2 uints) represent the lenth of the message.
            ulong numbits = (ulong)(l * 8); // Get number of bits from bytes
            M[14, numblocks - 1] = (uint)(numbits >> 32); // Get the high 32 bits
            M[15, numblocks - 1] = (uint)numbits; // Get the low 32 bits

            // The message is now padded
        }

        private String HashAlgorithm()
        {
            for (int i = 0; i < numblocks; i++)
            {
                // Initialise the registers
                uint a = H[0];
                uint b = H[1];
                uint c = H[2];
                uint d = H[3];
                uint e = H[4];
                uint f = H[5];
                uint g = H[6];
                uint h = H[7];

                uint[] W = new uint[64];

                for (int j = 0; j < 64; j++)
                {
                    // Calculate Wj first
                    if (j < 16)
                    {
                        W[j] = M[j, i];
                    }
                    else
                    {
                        W[j] = LCSigma1(W[j - 2]) + W[j - 7] + LCSigma0(W[j - 15]) + W[j - 16];
                    }

                    // Update the registers
                    uint T1 = h + UCSigma1(e) + Ch(e, f, g) + K[j] + W[j];
                    uint T2 = UCSigma0(a) + Maj(a, b, c);
                    h = g;
                    g = f;
                    f = e;
                    e = d + T1;
                    d = c;
                    c = b;
                    b = a;
                    a = T1 + T2;
                    //
                }
                //compute intermediate hash
                H[0] = a + H[0];
                H[1] = b + H[1];
                H[2] = c + H[2];
                H[3] = d + H[3];
                H[4] = e + H[4];
                H[5] = f + H[5];
                H[6] = g + H[6];
                H[7] = h + H[7];



            }
            return String.Format
            (
                "{0:X8}{1:X8}{2:X8}{3:X8}{4:X8}{5:X8}{6:X8}{7:X8}",
                H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]
            );
        }

        private uint Ch(uint x, uint y, uint z)
        {
            return (uint)((x & y) ^ (~x & z));
        }

        private uint Maj(uint x, uint y, uint z)
        {
            return (uint)((x & y) ^ (x & z) ^ (y & z));
        }

        private uint LCSigma0(uint x)
        {
            return S(x, 7) ^ S(x, 18) ^ x >> 3;
        }

        private uint LCSigma1(uint x)
        {
            return S(x, 17) ^ S(x, 19) ^ x >> 10;
        }

        private uint UCSigma0(uint x)
        {
            return S(x, 2) ^ S(x, 13) ^ S(x, 22);
        }

        private uint UCSigma1(uint x)
        {
            return S(x, 6) ^ S(x, 11) ^ S(x, 25);
        }

        private uint S(uint value, int bits) { return RotateRight(value, bits); }

        private uint RotateLeft(uint value, int count)
        {
            return (value << count) | (value >> (32 - count));
        }

        private uint RotateRight(uint value, int count)
        {
            return (value >> count) | (value << (32 - count));
        }

    }
}
