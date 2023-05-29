using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class SymmetricEncryption
{
    private static readonly byte[] Key = { 0x2A, 0xB4, 0xC6, 0x7F, 0x94, 0xE2, 0x33, 0x55, 0x6D, 0x9A, 0x1B, 0xC8, 0xF0, 0x0E, 0x83, 0x1F };
    private static readonly byte[] IV = { 0x3C, 0x5A, 0xE9, 0x71, 0x12, 0x3D, 0x96, 0xF8, 0x63, 0x29, 0x0F, 0xBA, 0x1C, 0x5B, 0x77, 0x8D };

    public static string Encrypt(string plainText)
    {
        byte[] encryptedBytes;

        using (Aes aes = Aes.Create())
        {
            aes.Key = Key;
            aes.IV = IV;

            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                {
                    byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                    cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                    cryptoStream.FlushFinalBlock();
                    encryptedBytes = memoryStream.ToArray();
                }
            }
        }

        return Convert.ToBase64String(encryptedBytes);
    }

    public static string Decrypt(string encryptedText)
    {
        string plainText;

        using (Aes aes = Aes.Create())
        {
            aes.Key = Key;
            aes.IV = IV;

            ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

            using (MemoryStream memoryStream = new MemoryStream(Convert.FromBase64String(encryptedText)))
            {
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader streamReader = new StreamReader(cryptoStream))
                    {
                        plainText = streamReader.ReadToEnd();
                    }
                }
            }
        }

        return plainText;
    }

    public static void Main()
    {
        Console.WriteLine("Enter a string to encrypt:");
        string input = Console.ReadLine();

        string encryptedText = Encrypt(input);
        Console.WriteLine($"Encrypted Text: {encryptedText}");

        string decryptedText = Decrypt(encryptedText);
        Console.WriteLine($"Decrypted Text: {decryptedText}");
    }
}

