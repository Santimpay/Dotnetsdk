using _dotNetSDK;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http.Headers;
using System.Reflection.PortableExecutable;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace _dotNetSDK
{
    public class SantimpaySdk
    {
        public string token;
        public string privateKey;
        public string merchantId;
        static HttpClient client = new HttpClient();

        public SantimpaySdk(string merchantId, string token, string privateKey)
        {
            this.token = token;
            this.privateKey = privateKey;
            this.merchantId = merchantId;
        }

        // to encrypt the private key with EC
      private static ECDsa GetEllipticCurveAlgorithm(string privateKey)
        {
            var keyParams = (ECPrivateKeyParameters)PrivateKeyFactory
                .CreateKey(Convert.FromBase64String(privateKey));

            var normalizedECPoint = keyParams.Parameters.G.Multiply(keyParams.D).Normalize();

            return ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.CreateFromValue(keyParams.PublicKeyParamSet.Id),
                D = keyParams.D.ToByteArrayUnsigned(),
                Q =
        {
            X = normalizedECPoint.XCoord.GetEncoded(),
            Y = normalizedECPoint.YCoord.GetEncoded()
        }
            });
        }

        public  string generateSignedToken(string amount, string paymentReason)
        {
           long Now = DateTimeOffset.Now.ToUnixTimeMilliseconds();
           long now= Now/ 1000;
           
            var handler = new JsonWebTokenHandler();

            string GATEWAY_MERCHANT_ID = "0f3a95d6-958d-457f-9031-dde2dad9ee17";

            var privateKey ="MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQguL/LFhkFaMVbqJeP" +
                     "vJ8N8oU98NQDBAY1WGc86ILT3tGhRANCAASqu+J41pkzEuCuznm4/Fnd9ZKwD7+z" +
                     "tIupn5uBB+RJLrm7fDWoKel9LKefNhUW5i5KvYhEBDlBbTDx8Yhhy4Es";
            
        

                    //    var privateKey ="MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg8NqhG3CnShfpfwVN" +
                    // "EsN6gd8EWqt4+pHaQKNDrxFY+M2hRANCAASEtRLC6DPwemVTxf7FSskiu/p1EZ9n" +
                    //  "pWGNXGhRkun7mSDzNr+Xx+0PIwg+KjBC9VGnwQ3h8gjeB31EZyF92hwU" ;
                
              var signatureAlgorithm = GetEllipticCurveAlgorithm(privateKey);

            ECDsaSecurityKey eCDsaSecurityKey = new ECDsaSecurityKey(signatureAlgorithm);



            string token = handler.CreateToken(new SecurityTokenDescriptor
            {
              Claims = new Dictionary<string, object> { { "amount", amount }, { "paymentreason", paymentReason },
                    { "merchantId", GATEWAY_MERCHANT_ID }, { "generated", now } },
                SigningCredentials = new SigningCredentials(eCDsaSecurityKey, "ES256")
            });

          return token;


        }
        
 async Task generatePaymentUrl(string id, string amount, string paymentReason, string successRedirectUrl, string failureRedirectUrl, string notifyUrl,string phoneNumber ,string cancelRedirectUrl)

        {
           
            HttpRequestMessage request;
            HttpResponseMessage response;
            client = new HttpClient();

            string SANTIMPAY_GATEWAY_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJwaG9uZU51bWJlciI6IisyNTE5MTAxMDEwMTAiLCJ3YWxsZXRJZCI6IjJkY2I0MzE0LTg0MTAtNDQ1YS05YjVlLTczNWE5YjE0OTZkZCIsInVzZXJJZCI6IjZkMjhhZmFiLTkzOWUtNGZjMC04Mzg1LTA4M2I2Zjc1ZTQwYSIsImRldmljZUlkIjoic2FtcG1tazIiLCJleHAiOjE2ODUwNzg2Mjd9.tJkcBi5FiSv9HDS1QLj0SsRxvvVbRFDaYHiVyx6no7w";

            string GATEWAY_MERCHANT_ID = "0f3a95d6-958d-457f-9031-dde2dad9ee17";
            
            string responsbody;

            var token = generateSignedToken("1", "coffee");

            request = new HttpRequestMessage(HttpMethod.Post, "https://services.santimpay.com/api/v1/gateway/initiate-payment");
           
            var stringdata = JsonConvert.SerializeObject(new Datasend()
            {
                id = id,
                amount = amount,
                reason = paymentReason,
                merchantId = GATEWAY_MERCHANT_ID,
                signedToken = token ,
                successRedirectUrl = successRedirectUrl,
                failureRedirectUrl = failureRedirectUrl,
                notifyUrl = notifyUrl,
                cancelRedirectUrl = cancelRedirectUrl,
                phoneNumber = phoneNumber,
                
            }); 


            var stringcontent = new StringContent(stringdata, Encoding.UTF8, "application/json");

            

            request.Content = stringcontent;
           

            List<NameValueHeaderValue> listheaders = new List<NameValueHeaderValue>();
           
            listheaders.Add(new NameValueHeaderValue("Accept","application/json"));
           

            listheaders.Add(new NameValueHeaderValue("Authorization", $"Bearer {SANTIMPAY_GATEWAY_TOKEN}"));

            foreach (var header in listheaders)
            {
                request.Headers.Add(header.Name, header.Value);
            }
            
          
             response = await client.SendAsync(request);
            responsbody = await response.Content.ReadAsStringAsync();
            string replacedUrl = responsbody.Replace("\\u0026", "&");

           Console.WriteLine(replacedUrl);
 }

 static async Task Main(string[] args)
        {
          string PRIVATE_KEY = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQguL/LFhkFaMVbqJeP" +
                     "vJ8N8oU98NQDBAY1WGc86ILT3tGhRANCAASqu+J41pkzEuCuznm4/Fnd9ZKwD7+z" +
                     "tIupn5uBB+RJLrm7fDWoKel9LKefNhUW5i5KvYhEBDlBbTDx8Yhhy4Es";

            string SANTIMPAY_GATEWAY_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJwaG9uZU51bWJlciI6IisyNTE5MTAxMDEwMTAiLCJ3YWxsZXRJZCI6IjJkY2I0MzE0LTg0MTAtNDQ1YS05YjVlLTczNWE5YjE0OTZkZCIsInVzZXJJZCI6IjZkMjhhZmFiLTkzOWUtNGZjMC04Mzg1LTA4M2I2Zjc1ZTQwYSIsImRldmljZUlkIjoic2FtcG1tazIiLCJleHAiOjE2ODUwNzg2Mjd9.tJkcBi5FiSv9HDS1QLj0SsRxvvVbRFDaYHiVyx6no7w";

            string GATEWAY_MERCHANT_ID = "0f3a95d6-958d-457f-9031-dde2dad9ee17";

            // client side pages to redirect user to after payment is completed/failed
            string successRedirectUrl = "https://santimpay.com";
            string failureRedirectUrl = "https://santimpay.com";

            // backend url to receive a status update (webhook)
            string notifyUrl = "https://santimpay.com";


           //pass phone number for the payload
            string phoneNumber = "";

            string cancelRedirectUrl ="https://santimpay.com";

            // custom ID used by merchant to identify the payment
            string id = "5";

           SantimpaySdk Client = new SantimpaySdk(GATEWAY_MERCHANT_ID, SANTIMPAY_GATEWAY_TOKEN, PRIVATE_KEY);

           var token = Client.generateSignedToken("1", "coffee");
     
           try
            {
                await Client.generatePaymentUrl(id, "1", "coffee", successRedirectUrl, failureRedirectUrl, notifyUrl,phoneNumber,cancelRedirectUrl);
               
                }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }


     }

    }
    
    //a data model for the requestbody
    
    public class Datasend
    {
        public string id { get; set; }
        public string amount { get; set;  }

        public string reason { get; set; }
        public string merchantId { get; set; }

        public string signedToken { get; set; }


        public string successRedirectUrl { get; set; }

        public string failureRedirectUrl { get; set; }
        public string notifyUrl { get; set; }

        public string cancelRedirectUrl { get; set; }
        public string phoneNumber { get; set; }
    }
       

    }
















    







        
