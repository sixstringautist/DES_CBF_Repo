using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace DES_CBF
{
    class MyDES_CBF
    {
        private byte[] bytekey;
        private string key;
        public string Key
        {
            get => key;
            set
            {
                var bytes = UnicodeEncoding.Unicode.GetBytes(value);
                bytekey = bytes;
                key = value;
                if (bytes.Length != 8)
                    throw new ArgumentOutOfRangeException("Длина ключа должна быть равна 8 байт");
                Encryptor = alg.CreateEncryptor(bytekey,alg.IV);
                Decryptor = alg.CreateDecryptor(bytekey, alg.IV);
            }
        }
        public byte[] IV { get; private set; }
        private byte[] InputToBytes(string _input)
        {
            return UnicodeEncoding.Unicode.GetBytes(_input);
        }
        private string BytesToString(byte[] _input)
        {
            return UnicodeEncoding.Unicode.GetString(_input);
        }
        DES alg = new DESCryptoServiceProvider();
        ICryptoTransform Encryptor;
        ICryptoTransform Decryptor;

        public byte[] GetEncryptedBytes(string _input)
        {
            var byteArr = UnicodeEncoding.Unicode.GetBytes(_input);
            return Encryptor.TransformFinalBlock(byteArr, 0, byteArr.Length);
        }
        public string GetDecryptedStringFromBytes(byte[] _input)
        {
            var dec_byte = Decryptor.TransformFinalBlock(_input, 0, _input.Length);
            return UnicodeEncoding.Unicode.GetString(dec_byte);
        }
        public MyDES_CBF()
        {
            alg.Mode = CipherMode.CFB;
            alg.GenerateKey();
            Key = UnicodeEncoding.Unicode.GetString(alg.Key);
            alg.GenerateIV();
            IV = alg.IV;
        }
        public MyDES_CBF(string _key)
        {
            alg.Mode = CipherMode.CFB;
            Key = _key;
            alg.GenerateIV();
            IV = alg.IV;
        }
    }
}
