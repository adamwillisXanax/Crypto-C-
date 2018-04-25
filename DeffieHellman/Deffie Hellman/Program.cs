using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static System.Console;
using System.IO;
using System.Security.Cryptography;
using Deffie_Hellman;

namespace Deffie_Hellman
{
    public class Person1
    {
        public static byte[] Person1PublicKey;

        static void Main(string[] args)
        {
            Write("Enter Some Text you like"+Environment.NewLine);
            string message = ReadLine();

            using (ECDiffieHellmanCng ecd = new ECDiffieHellmanCng())
            {
                ecd.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                ecd.HashAlgorithm = CngAlgorithm.Sha256;
                Person1PublicKey = ecd.PublicKey.ToByteArray();

                Person2 person2 = new Person2();
                CngKey k = CngKey.Import(person2.Person2PublicKey,CngKeyBlobFormat.EccPublicBlob);
                byte[] senderkey = ecd.DeriveKeyMaterial(CngKey.Import(person2.Person2PublicKey, CngKeyBlobFormat.EccPublicBlob));
                Send(senderkey,message,out byte[] encryptedMessage,out byte[] IV);
                person2.Receive(encryptedMessage, IV);
            }

        }
        public static void Send(byte[] key, string secretMessage, out byte[] encryptedMessage,out byte[] IV)
        {
            WriteLine(Environment.NewLine+ Environment.NewLine+"Sending Message...");
            using (Aes aes  = new AesCryptoServiceProvider())
            {
                aes.Key = key;
                IV = aes.IV;

                //Encrypt Message

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        byte[] plainTextMessage = Encoding.UTF8.GetBytes(secretMessage);
                        cs.Write(plainTextMessage,0,plainTextMessage.Length);
                        cs.Close();
                        encryptedMessage = ms.ToArray();

                    }
               }
            }
        }
    }
   public class Person2
    {
        public byte[] Person2PublicKey;
        private byte[] Key;

    public Person2()
    {
        using (ECDiffieHellmanCng ecd = new ECDiffieHellmanCng())
        {
            ecd.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            ecd.HashAlgorithm = CngAlgorithm.Sha256;
            Person2PublicKey = ecd.PublicKey.ToByteArray();
            Key = ecd.DeriveKeyMaterial(CngKey.Import(Person1.Person1PublicKey, CngKeyBlobFormat.EccPublicBlob));
        }

        WriteLine(Environment.NewLine + "Encrypted Message:" + Environment.NewLine);

        foreach (byte b in Key)
        {
            Write($"{b},");
        }
    }

        public void Receive(byte[] encryptedMessage, byte[] IV)
        {
        WriteLine("Receiving the message...");
        using (Aes aes = new AesCryptoServiceProvider())
        {
            aes.Key = Key;
            aes.IV = IV;

            //Decrypt and show
            using(MemoryStream ms = new MemoryStream())
            {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(encryptedMessage, 0, encryptedMessage.Length);
                        cs.Close();

                        string message = Encoding.UTF8.GetString(ms.ToArray());
                        WriteLine(Environment.NewLine);
                        WriteLine("Decrypted Message");
                        WriteLine(Environment.NewLine + message + Environment.NewLine);
                    }

            }

            WriteLine(Environment.NewLine + "Press Any Key to Continue...");
            ReadKey();
        }
        }
    }
}
