/*
 * This file is subject to the terms and conditions defined in
 * file 'license.txt', which is part of this source code package.
 */



using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace SteamKit2
{

    /// <summary>
    /// Handles encrypting and decrypting using the RSA public key encryption
    /// algorithm.
    /// </summary>
    public class RSACrypto : IDisposable
    {
        RSA rsa;

        /// <summary>
        /// Initializes a new instance of the <see cref="SteamKit2.RSACrypto"/> class.
        /// </summary>
        /// <param name="key">The public key to encrypt with.</param>
        public RSACrypto( byte[] key )
        {
            if ( key == null )
            {
                throw new ArgumentNullException( nameof(key) );
            }

            AsnKeyParser keyParser = new AsnKeyParser( key );

            rsa = RSA.Create();
            rsa.ImportParameters( keyParser.ParseRSAPublicKey() );
        }

        /// <summary>
        /// Encrypt the specified input.
        /// </summary>
        /// <returns>The encrypted input.</returns>
        /// <param name="input">The input to encrypt.</param>
        public byte[] Encrypt( byte[] input )
        {
            if ( input == null )
            {
                throw new ArgumentNullException( nameof(input) );
            }

            return rsa.Encrypt( input, RSAEncryptionPadding.OaepSHA1 );
        }

        /// <summary>
        /// Disposes of this class.
        /// </summary>
        public void Dispose()
        {
            ( ( IDisposable )rsa ).Dispose();
        }
    }

    /// <summary>
    /// Provides Crypto functions used in Steam protocols
    /// </summary>
    public static class CryptoHelper
    {
        /// <summary>
        /// Performs an SHA1 hash of an input byte array
        /// </summary>
        public static byte[] SHAHash( byte[] input )
        {
            if ( input == null )
            {
                throw new ArgumentNullException( nameof(input) );
            }

            using ( var sha = SHA1.Create() )
            {
                return sha.ComputeHash( input );
            }
        }

        /// <summary>
        /// Encrypts using AES/CBC/PKCS7 an input byte array with a given key and IV
        /// </summary>
        public static byte[] AESEncrypt( byte[] input, byte[] key, byte[] iv )
        {
            if ( input == null )
            {
                throw new ArgumentNullException( nameof(input) );
            }
            
            if ( key == null )
            {
                throw new ArgumentNullException( nameof(key) );
            }
            
            if ( iv == null )
            {
                throw new ArgumentNullException( nameof(iv) );
            }

            using ( var aes = Aes.Create() )
            {
                aes.BlockSize = 128;
                aes.KeySize = 128;

                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using ( var aesTransform = aes.CreateEncryptor( key, iv ) )
                using ( var ms = new MemoryStream() )
                using ( var cs = new CryptoStream( ms, aesTransform, CryptoStreamMode.Write ) )
                {
                    cs.Write( input, 0, input.Length );
                    cs.FlushFinalBlock();
                    
                    return ms.ToArray();
                }
            }
        }

        /// <summary>
        /// Decrypts an input byte array using AES/CBC/PKCS7 with a given key and IV
        /// </summary>
        public static byte[] AESDecrypt( byte[] input, byte[] key, byte[] iv )
        {
            if ( input == null )
            {
                throw new ArgumentNullException( nameof(input) );
            }
            
            if ( key == null )
            {
                throw new ArgumentNullException( nameof(key) );
            }
            
            if ( iv == null )
            {
                throw new ArgumentNullException( nameof(iv) );
            }

            using ( var aes = Aes.Create() )
            {
                aes.BlockSize = 128;
                aes.KeySize = 128;

                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                byte[] plainText = new byte[ input.Length ];
                int outLen = 0;

                using ( var aesTransform = aes.CreateDecryptor( key, iv ) )
                using ( var ms = new MemoryStream( input ) )
                using ( var cs = new CryptoStream( ms, aesTransform, CryptoStreamMode.Read ) )
                {
                    outLen = cs.Read( plainText, 0, plainText.Length );
                }

                byte[] output = new byte[ outLen ];
                Array.Copy( plainText, 0, output, 0, output.Length );

                return output;
            }
        }

        /// <summary>
        /// Performs an encryption using AES/CBC/PKCS7 with an input byte array and key, with a random IV prepended using AES/ECB/None
        /// </summary>
        public static byte[] SymmetricEncryptWithIV(byte[] input, byte[] key, byte[] iv)
        {
            if (input == null)
            {
                throw new ArgumentNullException(nameof(input));
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (iv == null)
            {
                throw new ArgumentNullException(nameof(iv));
            }

#if FEATURE_SPAN
            return SymmetricEncryptWithIV(input.AsSpan(), key, iv);
        }

        /// <summary>
        /// Performs an encryption using AES/CBC/PKCS7 with an input byte array and key, with a random IV prepended using AES/ECB/None
        /// </summary>
        public static byte[] SymmetricEncryptWithIV(ReadOnlySpan<byte> input, byte[] key, byte[] iv)
        {
#endif

            DebugLog.Assert( key.Length == 32, "CryptoHelper", "SymmetricEncrypt used with non 32 byte key!" );

            using ( var aes = Aes.Create() )
            {
                aes.BlockSize = 128;
                aes.KeySize = 256;

                byte[] cryptedIv;
                
                // encrypt iv using ECB and provided key
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;

                using ( var aesTransform = aes.CreateEncryptor( key, null ) )
                {
                    cryptedIv = aesTransform.TransformFinalBlock( iv, 0, iv.Length );
                }

                // encrypt input plaintext with CBC using the generated (plaintext) IV and the provided key
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using ( var aesTransform = aes.CreateEncryptor( key, iv ) )
                using ( var ms = new MemoryStream() )
                using ( var cs = new CryptoStream( ms, aesTransform, CryptoStreamMode.Write ) )
                {
#if FEATURE_SPAN
                    cs.Write(input);
#else
                    cs.Write(input, 0, input.Length);
#endif
                    cs.FlushFinalBlock();

                    var cipherText = ms.ToArray();

                    // final output is 16 byte ecb crypted IV + cbc crypted plaintext
                    var output = new byte[ cryptedIv.Length + cipherText.Length ];

                    Array.Copy( cryptedIv, 0, output, 0, cryptedIv.Length );
                    Array.Copy( cipherText, 0, output, cryptedIv.Length, cipherText.Length );

                    return output;
                }
            }
        }

        /// <summary>
        /// Performs an encryption using AES/CBC/PKCS7 with an input byte array and key, with a random IV prepended using AES/ECB/None
        /// </summary>
        public static byte[] SymmetricEncrypt( byte[] input, byte[] key )
        {
            if ( input == null )
            {
                throw new ArgumentNullException( nameof(input) );
            }
            
            if ( key == null )
            {
                throw new ArgumentNullException( nameof(key) );
            }

            var iv = GenerateRandomBlock( 16 );
            return SymmetricEncryptWithIV( input, key, iv );
        }

        /// <summary>
        /// Performs an encryption using AES/CBC/PKCS7 with an input byte array and key, with a IV (comprised of random bytes and the HMAC-SHA1 of the random bytes and plaintext) prepended using AES/ECB/None
        /// </summary>
        public static byte[] SymmetricEncryptWithHMACIV(byte[] input, byte[] key, byte[] hmacSecret)
        {
            if (input == null)
            {
                throw new ArgumentNullException(nameof(input));
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (hmacSecret == null)
            {
                throw new ArgumentNullException(nameof(hmacSecret));
            }

#if FEATURE_SPAN
            return SymmetricEncryptWithHMACIV(input.AsSpan(), key, hmacSecret);
        }

        /// <summary>
        /// Performs an encryption using AES/CBC/PKCS7 with an input byte array and key, with a IV (comprised of random bytes and the HMAC-SHA1 of the random bytes and plaintext) prepended using AES/ECB/None
        /// </summary>
        public static byte[] SymmetricEncryptWithHMACIV(ReadOnlySpan<byte> input, byte[] key, byte[] hmacSecret)
        {

            if (hmacSecret == null)
            {
                throw new ArgumentNullException(nameof(hmacSecret));
            }
#endif

            // IV is HMAC-SHA1(Random(3) + Plaintext) + Random(3). (Same random values for both)
            const int RandomDataLength = 3; // BACKPORT ME

#if FEATURE_SPAN
            Span<byte> iv = stackalloc byte[16];
            var randomData = iv.Slice(iv.Length - RandomDataLength, RandomDataLength);
            RandomNumberGenerator.Fill(randomData);
#else
            var iv = new byte[ 16 ];
            FillRandomBlock( iv, iv.Length - RandomDataLength, RandomDataLength);
#endif

            using ( var hmac = new HMACSHA1( hmacSecret ) )
            using ( var ms = new MemoryStream() )
            {
#if FEATURE_SPAN
                ms.Write(randomData);
                ms.Write(input);
#else
                ms.Write( iv, iv.Length - RandomDataLength, RandomDataLength);
                ms.Write( input, 0, input.Length );
#endif


#if FEATURE_SPAN
                Span<byte> hash = stackalloc byte[20];
                var buffer = new ReadOnlySpan<byte>(ms.GetBuffer(), 0, (int)ms.Position);
                if (!hmac.TryComputeHash(buffer, hash, out var hmacLength))
                {
                    throw new InvalidOperationException("Not enough space allocated for hmac.");
                }
                hash.Slice(0, iv.Length - RandomDataLength).CopyTo(iv);
#else
                ms.Seek(0, SeekOrigin.Begin);
                var hash = hmac.ComputeHash( ms );
                Array.Copy( hash, iv, iv.Length - RandomDataLength);
#endif
            }
            
            return SymmetricEncryptWithIV( input, key, iv.ToArray() );
        }

        /// <summary>
        /// Decrypts using AES/CBC/PKCS7 with an input byte array and key, using the random IV prepended using AES/ECB/None
        /// </summary>
        public static byte[] SymmetricDecrypt( byte[] input, byte[] key )
        {
            if ( input == null )
            {
                throw new ArgumentNullException( nameof(input) );
            }
            
            if ( key == null )
            {
                throw new ArgumentNullException( nameof(key) );
            }
            
            return SymmetricDecrypt( input, key, out _ );
        }

        /// <summary>
        /// Decrypts using AES/CBC/PKCS7 with an input byte array and key, using the IV (comprised of random bytes and the HMAC-SHA1 of the random bytes and plaintext) prepended using AES/ECB/None
        /// </summary>
        public static byte[] SymmetricDecryptHMACIV( byte[] input, byte[] key, byte[] hmacSecret )
        {
            if ( input == null )
            {
                throw new ArgumentNullException( nameof(input) );
            }
            
            if ( key == null )
            {
                throw new ArgumentNullException( nameof(key) );
            }
            
            if ( hmacSecret == null )
            {
                throw new ArgumentNullException( nameof(hmacSecret) );
            }

            Debug.Assert( key.Length >= 16 );
            var truncatedKeyForHmac = new byte[ 16 ];
            Array.Copy( key, 0, truncatedKeyForHmac, 0, truncatedKeyForHmac.Length );

            var plaintextData = SymmetricDecrypt( input, key, out var iv );

            // validate HMAC
            byte[] hmacBytes;
            using ( var hmac = new HMACSHA1( hmacSecret ) )
            using ( var ms = new MemoryStream() )
            {
                ms.Write( iv, iv.Length - 3, 3 );
                ms.Write( plaintextData, 0, plaintextData.Length );
                ms.Seek( 0, SeekOrigin.Begin );

                hmacBytes = hmac.ComputeHash( ms );
            }

            if ( !hmacBytes.Take( iv.Length - 3 ).SequenceEqual( iv.Take( iv.Length - 3 ) ) )
            {
                throw new CryptographicException( string.Format( CultureInfo.InvariantCulture, "{0} was unable to decrypt packet: HMAC from server did not match computed HMAC.", nameof(NetFilterEncryption) ) );
            }

            return plaintextData;
        }

        /// <summary>
        /// Decrypts using AES/CBC/PKCS7 with an input byte array and key, using the random IV prepended using AES/ECB/None
        /// </summary>
        static byte[] SymmetricDecrypt( byte[] input, byte[] key, out byte[] iv )
        {
            if ( input == null )
            {
                throw new ArgumentNullException( nameof(input) );
            }
            
            if ( key == null )
            {
                throw new ArgumentNullException( nameof(key) );
            }

            DebugLog.Assert( key.Length == 32, "CryptoHelper", "SymmetricDecrypt used with non 32 byte key!" );

            using ( var aes = Aes.Create() )
            {
                aes.BlockSize = 128;
                aes.KeySize = 256;

                // first 16 bytes of input is the ECB encrypted IV
                var cryptedIv = input.AsSpan( 0, 16 );

                // the rest is ciphertext
                var cipherText = input.AsSpan( cryptedIv.Length );

                // decrypt the IV using ECB
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;

                using ( var aesTransform = aes.CreateDecryptor( key, null ) )
                {
                    iv = aesTransform.TransformFinalBlock( cryptedIv.ToArray(), 0, cryptedIv.Length );
                }

                // decrypt the remaining ciphertext in cbc with the decrypted IV
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using ( var aesTransform = aes.CreateDecryptor( key, iv ) )
                using ( var ms = new MemoryStream( input, cryptedIv.Length, cipherText.Length ) ) // BACKPORT
                using ( var cs = new CryptoStream( ms, aesTransform, CryptoStreamMode.Read ) )
                {
                    // plaintext is never longer than ciphertext
                    byte[] plaintext = new byte[ cipherText.Length ];

                    int len = cs.Read( plaintext, 0, plaintext.Length );
                    Array.Resize(ref plaintext, len);
                    byte[] output = new byte[ len ];
                    Array.Copy( plaintext, 0, output, 0, len );

                    return output;
                }
            }
        }

        /// <summary>
        /// Verifies and performs a symmetricdecrypt on the input using the given password as a key
        /// </summary>
        public static byte[] VerifyAndDecryptPassword( byte[] input, string password )
        {
            if ( input == null )
            {
                throw new ArgumentNullException( nameof(input) );
            }
            
            if ( password == null )
            {
                throw new ArgumentNullException( nameof(password) );
            }

            byte[] key, hash;
            using( var sha256 = SHA256.Create() )
            {
                byte[] password_bytes = Encoding.UTF8.GetBytes( password );
                key = sha256.ComputeHash( password_bytes );
            }
            using( HMACSHA1 hmac = new HMACSHA1(key) )
            {
                hash = hmac.ComputeHash( input, 0, 32 );
            }

            for ( int i = 32; i < input.Length; i++ )
                if ( input[ i ] != hash[ i % 32 ] )
                    return null;

            byte[] encrypted = new byte[ 32 ];
            Array.Copy( input, encrypted, encrypted.Length );

            return CryptoHelper.SymmetricDecrypt( encrypted, key );
        }

        /// <summary>
        /// Decrypts using AES/ECB/PKCS7
        /// </summary>
        public static byte[] SymmetricDecryptECB( byte[] input, byte[] key )
        {
            if ( input == null )
            {
                throw new ArgumentNullException( nameof(input) );
            }
            
            if ( key == null )
            {
                throw new ArgumentNullException( nameof(key) );
            }
            
            DebugLog.Assert( key.Length == 32, "CryptoHelper", "SymmetricDecryptECB used with non 32 byte key!" );

            using ( var aes = Aes.Create() )
            {
                aes.BlockSize = 128;
                aes.KeySize = 256;
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.PKCS7;

                using ( var aesTransform = aes.CreateDecryptor( key, null ) )
                {
                    byte[] output = aesTransform.TransformFinalBlock( input, 0, input.Length );

                    return output;
                }
            }
        }

        /// <summary>
        /// Performs CRC32 on an input byte array using the CrcStandard.Crc32Bit parameters
        /// </summary>
        public static byte[] CRCHash( byte[] input )
        {
            if ( input == null )
            {
                throw new ArgumentNullException( nameof(input) );
            }

            using ( var crc = new Crc32() )
            {
                byte[] hash = crc.ComputeHash( input );
                Array.Reverse( hash );

                return hash;
            }
        }

        /// <summary>
        /// Performs an Adler32 on the given input
        /// </summary>
        public static byte[] AdlerHash( ReadOnlySpan<byte> input )
        {
            if ( input == null )
            {
                throw new ArgumentNullException( nameof(input) );
            }
            
            uint a = 0, b = 0;
            for ( int i = 0 ; i < input.Length ; i++ )
            {
                a = ( a + input[ i ] ) % 65521;
                b = ( b + a ) % 65521;
            }
            return BitConverter.GetBytes( a | ( b << 16 ) );
        }

        /// <summary>
        /// Generate an array of random bytes given the input length
        /// </summary>
        public static byte[] GenerateRandomBlock( int size )
        {
            using ( var rng = RandomNumberGenerator.Create() )
            {
                var block = new byte[ size ];

                rng.GetBytes( block );

                return block;
            }
        }

#if !FEATURE_SPAN
        /// <summary>
        /// Fills an array with random bytes.
        /// </summary>
        static void FillRandomBlock( byte[] data, int offset, int count)
        {
            using ( var rng = RandomNumberGenerator.Create() )
            {
                rng.GetBytes( data, offset, count );
            }
        }
#endif

    }
}
