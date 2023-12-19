using EncryptionDecryptionApi.ViewModel;
using Microsoft.AspNetCore.Mvc;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace EncryptionDecryptionApi.Controllers
{

    [Route("api/[controller]")]
    [ApiController]
    public class EncryptionDecrptionController : ControllerBase
    {
        public readonly IConfiguration _configuration;
        public EncryptionDecrptionController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost]
        [Route("Encryption")]
        public CommonResponse Encryption(EncryptionReq encrptionReq)
        {
            CommonResponse response = new CommonResponse();
            try
            {
                if (encrptionReq.PlainText.Trim().Length >= 1)
                {
                    #region MyRegion
                    //byte[] iv = new byte[16];
                    //using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
                    //{
                    //    rng.GetBytes(iv);
                    //} 
                    #endregion

                    response.Data = EncryptString(_configuration["EncrptionDecryption:Key"], encrptionReq.PlainText.Trim());
                    response.StatusCode = HttpStatusCode.OK;
                    response.Status = true;
                    response.Message = "Data are successfully encrypted";
                }
                else
                {
                    response.StatusCode = HttpStatusCode.BadRequest;
                    response.Message = "data are null";
                }
            }
            catch { throw; }
            return response;
        }

        [NonAction]
        public string EncryptString(string key, string plainInput)
        {
            byte[] iv = Encoding.UTF8.GetBytes(_configuration["EncrptionDecryption:iv"]);
            byte[] cipheredtext;
            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 128;
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = iv;
                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter streamWriter = new StreamWriter((Stream)cryptoStream))
                        {
                            streamWriter.Write(plainInput);
                        }
                        cipheredtext = memoryStream.ToArray();
                    }
                }
            }
            return Convert.ToBase64String(cipheredtext);
        }

        [HttpPost]
        [Route("Decryption")]
        public CommonResponse Decryption(DecryptionReq decryptionReq)
        {
            CommonResponse response = new CommonResponse();
            try
            {
                if (decryptionReq.CipherText.Trim().Length >= 1)
                {
                    response.Data = DecryptString(_configuration["EncrptionDecryption:Key"], decryptionReq.CipherText.Trim()); ;
                    response.StatusCode = HttpStatusCode.OK;
                    response.Status = true;
                    response.Message = "Data are successfully decrypted";
                }
                else
                {
                    response.StatusCode = HttpStatusCode.BadRequest;
                    response.Message = "data are null";
                }
            }
            catch { throw; }

            return response;
        }

        [NonAction]
        public string DecryptString(string key, string cipherText)
        {
            //byte[] iv = new byte[16];

            byte[] iv = Encoding.UTF8.GetBytes(_configuration["EncrptionDecryption:iv"]);

            //byte[] iv = Convert.FromBase64String(_configuration["EncrptionSecryption:iv"]);

            string simpletext = string.Empty;

            byte[] buffer = Convert.FromBase64String(cipherText);

            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 128;
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = iv;
                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                using (MemoryStream memoryStream = new MemoryStream(buffer))
                {
                    using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader streamReader = new StreamReader((Stream)cryptoStream))
                        {
                            simpletext = streamReader.ReadToEnd();
                        }
                    }
                }
            }
            return simpletext;
        }

    }
}
