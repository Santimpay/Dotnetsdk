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
using System;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;
using System.Text.Json;

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

        private static ECDsa GetEllipticCurvePublicKey(string publicKey)
     {
    var keyParams = (ECPublicKeyParameters)PublicKeyFactory
        .CreateKey(Convert.FromBase64String(publicKey));

    return ECDsa.Create(new ECParameters
    {
        Curve = ECCurve.NamedCurves.nistP256, 
        Q = new ECPoint
        {
            X = keyParams.Q.XCoord.GetEncoded(),
            Y = keyParams.Q.YCoord.GetEncoded()
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

       public  string generateSignedTokenforB2C(string amount, string paymentReason,string paymentMethod,string phoneNumber)
        {
           long Now = DateTimeOffset.Now.ToUnixTimeMilliseconds();
           long now= Now/ 1000;
           
            var handler = new JsonWebTokenHandler();

            string GATEWAY_MERCHANT_ID = "0f3a95d6-958d-457f-9031-dde2dad9ee17";

            var privateKey ="MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQguL/LFhkFaMVbqJeP" +
                     "vJ8N8oU98NQDBAY1WGc86ILT3tGhRANCAASqu+J41pkzEuCuznm4/Fnd9ZKwD7+z" +
                     "tIupn5uBB+RJLrm7fDWoKel9LKefNhUW5i5KvYhEBDlBbTDx8Yhhy4Es";
            
                
              var signatureAlgorithm = GetEllipticCurveAlgorithm(privateKey);

            ECDsaSecurityKey eCDsaSecurityKey = new ECDsaSecurityKey(signatureAlgorithm);




            string token = handler.CreateToken(new SecurityTokenDescriptor
            {
              Claims = new Dictionary<string, object> { { "amount", amount }, { "paymentreason", paymentReason },
             { "merchantId", GATEWAY_MERCHANT_ID }, {"paymentMethod", paymentMethod},{"phoneNumber",phoneNumber},{ "generated", now } },
                SigningCredentials = new SigningCredentials(eCDsaSecurityKey, "ES256")
            });

          return token;


        }

       public string  generateSignedTokenForGetTransaction(string id) {
          long Now = DateTimeOffset.Now.ToUnixTimeMilliseconds();
           long now= Now/ 1000;
           
            var handler = new JsonWebTokenHandler();

            string GATEWAY_MERCHANT_ID = "0f3a95d6-958d-457f-9031-dde2dad9ee17";

            var privateKey ="MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQguL/LFhkFaMVbqJeP" +
                     "vJ8N8oU98NQDBAY1WGc86ILT3tGhRANCAASqu+J41pkzEuCuznm4/Fnd9ZKwD7+z" +
                     "tIupn5uBB+RJLrm7fDWoKel9LKefNhUW5i5KvYhEBDlBbTDx8Yhhy4Es";
                
              var signatureAlgorithm = GetEllipticCurveAlgorithm(privateKey);

            ECDsaSecurityKey eCDsaSecurityKey = new ECDsaSecurityKey(signatureAlgorithm);




            string token = handler.CreateToken(new SecurityTokenDescriptor
            {
              Claims = new Dictionary<string, object> { { "id", id }, { "merId", GATEWAY_MERCHANT_ID },
             { "generated", now } },
                SigningCredentials = new SigningCredentials(eCDsaSecurityKey, "ES256")
            });

          return token;

  }



public async Task<bool> validateEs256JwtTokenAsync(string tokenString) {
      var publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEo5FyFVlH0XGCvSo/9kBq2jr7KId2" +
                            "DskcmjMPXAT/Sy8gjOyWJjBOgT24tj1PA7dgmohkBnF/+pjwlziNfxjrPg==";

    try
    {
        var securityTokenHandler = new JwtSecurityTokenHandler();

        var signatureAlgorithm = GetEllipticCurvePublicKey(publicKey);


         var token = securityTokenHandler.ReadJwtToken(tokenString);
        
           if (token.Header["alg"]?.ToString() != "ES256" || token.Header["typ"]?.ToString() != "JWT")
        {
            Console.WriteLine("Invalid token header");
            return false; // Token header is invalid
        }

        // Extract the issuer from the token
        var issuer = token.Issuer;
        

        var expectedIssuer = "services.santimpay.com";

      

        // Check if the issuer matches the expected value
        if (issuer != expectedIssuer)
        {
            Console.WriteLine("Invalid issuer");
            return false; // Token is invalid due to an incorrect issuer
        }

       
        
        var validationParameters = new TokenValidationParameters()
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new ECDsaSecurityKey(signatureAlgorithm),
            ValidateIssuer = true, 
            ValidIssuer = issuer, 
            ValidateAudience = true, 
            ValidAudience = "services.santimpay.com", 
            ValidateLifetime = true 
        };

        // Validate the token asynchronously
        var claimsPrincipal = await securityTokenHandler.ValidateTokenAsync(tokenString, validationParameters);

       
        return true; 
    }
    catch (System.Exception e)
    {
        Console.WriteLine($"Token validation failed: {e.Message}");
        return false; // Token is invalid
    }
}


  async Task SendToCustomer(string id,string amount,string paymentReason,string phoneNumber,string paymentMethod,string notifyUrl)
   {
    HttpRequestMessage request;
            HttpResponseMessage response;
            client = new HttpClient();

           
            string GATEWAY_MERCHANT_ID = "0f3a95d6-958d-457f-9031-dde2dad9ee17";
            
            string responsbody;

            var token = generateSignedTokenforB2C("1", "coffee",paymentMethod, phoneNumber);

            request = new HttpRequestMessage(HttpMethod.Post, "https://services.santimpay.com/api/v1/gateway/payout-transfer");
           
            var stringdata = JsonConvert.SerializeObject(new Datasend()
            {
                id = id,
                clientReference=id,
                amount = amount,
                reason = paymentReason,
                merchantId = GATEWAY_MERCHANT_ID,
                signedToken = token ,
                receiverAccountNumber = phoneNumber,
                notifyUrl = notifyUrl,
                paymentMethod=paymentMethod
                
            }); 


            var stringcontent = new StringContent(stringdata, Encoding.UTF8, "application/json");
             request.Content = stringcontent;
             response = await client.SendAsync(request);
            responsbody = await response.Content.ReadAsStringAsync();
            

           Console.WriteLine(responsbody);
}
  

        
 async Task GeneratePaymentUrl(string id, string amount, string paymentReason, string successRedirectUrl, string failureRedirectUrl, string notifyUrl,string phoneNumber ,string cancelRedirectUrl)

        {
           
            HttpRequestMessage request;
            HttpResponseMessage response;
            client = new HttpClient();

            string SANTIMPAY_GATEWAY_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJwaG9uZU51bWJlciI6IisyNTE5MTAxMDEwMTAiLCJ3YWxsZXRJZCI6IjJkY2I0MzE0LTg0MTAtNDQ1YS05YjVlLTczNWE5YjE0OTZkZCIsInVzZXJJZCI6IjZkMjhhZmFiLTkzOWUtNGZjMC04Mzg1LTA4M2I2Zjc1ZTQwYSIsImRldmljZUlkIjoic2FtcG1tazIiLCJleHAiOjE2ODUwNzg2Mjd9.tJkcBi5FiSv9HDS1QLj0SsRxvvVbRFDaYHiVyx6no7w";

            string GATEWAY_MERCHANT_ID = "0f3a95d6-958d-457f-9031-dde2dad9ee17";

            // string signed_token ="eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eG5JZCI6IjNlOTc4MDA5LWYxNGUtNGViNy05MzBiLWY4ODc2OTM2YjlkZSIsImNyZWF0ZWRfYXQiOiIyMDI0LTEwLTMxVDE3OjUxOjA1LjU5OTI1N1oiLCJ1cGRhdGVkX2F0IjoiMjAyNC0xMC0zMVQxNzo1MzowMC45NTQzN1oiLCJ0aGlyZFBhcnR5SWQiOiI0MDgiLCJ0cmFuc2FjdGlvblR5cGUiOiIiLCJtZXJJZCI6IjBmM2E5NWQ2LTk1OGQtNDU3Zi05MDMxLWRkZTJkYWQ5ZWUxNyIsIm1lck5hbWUiOiJTZWxlY3Qgc3BvcnQgYmV0dGluZyIsImFkZHJlc3MiOiJBQSIsImFtb3VudCI6IjAuOTczNSIsImNvbW1pc3Npb24iOiIwLjAyNjUiLCJ0b3RhbEFtb3VudCI6IjEiLCJjdXJyZW5jeSI6IkVUQiIsInJlYXNvbiI6ImNvZmZlZSIsIm1zaXNkbiI6IisyNTE5MDkxMjYzMjQiLCJhY2NvdW50TnVtYmVyIjoiIiwiY2xpZW50UmVmZXJlbmNlIjoiIiwicGF5bWVudFZpYSI6IlRlbGViaXJyIiwicmVmSWQiOiI2MmQ0N2Q4NC02YWYzLTQ3OGUtODhmOC0xOGU0OTE3OTlkMjQiLCJzdWNjZXNzUmVkaXJlY3RVcmwiOiJodHRwczovL3NhbnRpbXBheS5jb20iLCJmYWlsdXJlUmVkaXJlY3RVcmwiOiJodHRwczovL3NhbnRpbXBheS5jb20iLCJjYW5jZWxSZWRpcmVjdFVybCI6Imh0dHBzOi8vc2FudGltcGF5LmNvbSIsImNvbW1pc3Npb25BbW91bnRJblBlcmNlbnQiOjAuMDExNSwicHJvdmlkZXJDb21taXNzaW9uQW1vdW50SW5QZXJjZW50IjowLjAxNSwiY29tbWlzc2lvbkZyb21DdXN0b21lciI6ZmFsc2UsInZhdEFtb3VudEluUGVyY2VudCI6IjAuMDE1IiwibG90dGVyeVRheCI6IjAiLCJtZXNzYWdlIjoicGF5bWVudCBzdWNjZXNzZnVsIiwidXBkYXRlVHlwZSI6IiIsIlN0YXR1cyI6IkNPTVBMRVRFRCIsIlN0YXR1c1JlYXNvbiI6IiIsIlJlY2VpdmVyV2FsbGV0SUQiOiIiLCJpYXQiOjE3MzAzOTcxODAsImlzcyI6InNlcnZpY2VzLnNhbnRpbXBheS5jb20ifQ.SM345qdVTPzG14-Ks1-J-fk2eQyta9OCKNPv_XYYF0IkoU7LtHcCRWdqsLlk0TYz39F3VWYvbE_d86kJEsUmww";
           

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


async Task CheckTransactionStatus(string id)
{
    HttpRequestMessage request;
            HttpResponseMessage response;
            client = new HttpClient();

           
            string GATEWAY_MERCHANT_ID = "0f3a95d6-958d-457f-9031-dde2dad9ee17";
            
            string responsbody;

            var token = generateSignedTokenForGetTransaction(id);

            request = new HttpRequestMessage(HttpMethod.Post, "https://services.santimpay.com/api/v1/gateway/fetch-transaction-status");
           
            var stringdata = JsonConvert.SerializeObject(new Datasend()
            {
                id = id,
               merchantId=GATEWAY_MERCHANT_ID,
               signedToken= token
               
                
            }); 


            var stringcontent = new StringContent(stringdata, Encoding.UTF8, "application/json");

            

            request.Content = stringcontent;
           

            // List<NameValueHeaderValue> listheaders = new List<NameValueHeaderValue>();
           
            // listheaders.Add(new NameValueHeaderValue("Accept","application/json"));
           

            // listheaders.Add(new NameValueHeaderValue("Authorization", $"Bearer {SANTIMPAY_GATEWAY_TOKEN}"));

            // foreach (var header in listheaders)
            // {
            //     request.Headers.Add(header.Name, header.Value);
            // }
            
          
             response = await client.SendAsync(request);
            responsbody = await response.Content.ReadAsStringAsync();
         

           Console.WriteLine(responsbody);
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
            string notifyUrl = "https://webhook.site/1f11e73f-6a44-4c65-9bde-0292e56d3f61";
            // "https://santimpay.com";

          //pass phone number for the payload
            string phoneNumber = "+251909126324";

            string paymentMethod = "";

            string cancelRedirectUrl ="https://santimpay.com";

            // custom ID used by merchant to identify the payment
            string id = "4117";


 // signed-token token from the callback for validation
            string signed_token ="eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eG5JZCI6IjNlOTc4MDA5LWYxNGUtNGViNy05MzBiLWY4ODc2OTM2YjlkZSIsImNyZWF0ZWRfYXQiOiIyMDI0LTEwLTMxVDE3OjUxOjA1LjU5OTI1N1oiLCJ1cGRhdGVkX2F0IjoiMjAyNC0xMC0zMVQxNzo1MzowMC45NTQzN1oiLCJ0aGlyZFBhcnR5SWQiOiI0MDgiLCJ0cmFuc2FjdGlvblR5cGUiOiIiLCJtZXJJZCI6IjBmM2E5NWQ2LTk1OGQtNDU3Zi05MDMxLWRkZTJkYWQ5ZWUxNyIsIm1lck5hbWUiOiJTZWxlY3Qgc3BvcnQgYmV0dGluZyIsImFkZHJlc3MiOiJBQSIsImFtb3VudCI6IjAuOTczNSIsImNvbW1pc3Npb24iOiIwLjAyNjUiLCJ0b3RhbEFtb3VudCI6IjEiLCJjdXJyZW5jeSI6IkVUQiIsInJlYXNvbiI6ImNvZmZlZSIsIm1zaXNkbiI6IisyNTE5MDkxMjYzMjQiLCJhY2NvdW50TnVtYmVyIjoiIiwiY2xpZW50UmVmZXJlbmNlIjoiIiwicGF5bWVudFZpYSI6IlRlbGViaXJyIiwicmVmSWQiOiI2MmQ0N2Q4NC02YWYzLTQ3OGUtODhmOC0xOGU0OTE3OTlkMjQiLCJzdWNjZXNzUmVkaXJlY3RVcmwiOiJodHRwczovL3NhbnRpbXBheS5jb20iLCJmYWlsdXJlUmVkaXJlY3RVcmwiOiJodHRwczovL3NhbnRpbXBheS5jb20iLCJjYW5jZWxSZWRpcmVjdFVybCI6Imh0dHBzOi8vc2FudGltcGF5LmNvbSIsImNvbW1pc3Npb25BbW91bnRJblBlcmNlbnQiOjAuMDExNSwicHJvdmlkZXJDb21taXNzaW9uQW1vdW50SW5QZXJjZW50IjowLjAxNSwiY29tbWlzc2lvbkZyb21DdXN0b21lciI6ZmFsc2UsInZhdEFtb3VudEluUGVyY2VudCI6IjAuMDE1IiwibG90dGVyeVRheCI6IjAiLCJtZXNzYWdlIjoicGF5bWVudCBzdWNjZXNzZnVsIiwidXBkYXRlVHlwZSI6IiIsIlN0YXR1cyI6IkNPTVBMRVRFRCIsIlN0YXR1c1JlYXNvbiI6IiIsIlJlY2VpdmVyV2FsbGV0SUQiOiIiLCJpYXQiOjE3MzAzOTcxODAsImlzcyI6InNlcnZpY2VzLnNhbnRpbXBheS5jb20ifQ.SM345qdVTPzG14-Ks1-J-fk2eQyta9OCKNPv_XYYF0IkoU7LtHcCRWdqsLlk0TYz39F3VWYvbE_d86kJEsUmww";
           



           SantimpaySdk Client = new SantimpaySdk(GATEWAY_MERCHANT_ID, SANTIMPAY_GATEWAY_TOKEN, PRIVATE_KEY);

           var token = Client.generateSignedToken("1", "coffee");
     

           try
            {
                await Client.GeneratePaymentUrl(id, "1", "coffee", successRedirectUrl, failureRedirectUrl, notifyUrl,phoneNumber,cancelRedirectUrl);
               
                }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
                 

                 //Validate token
            try
            {
                var isTokenValid = await Client.validateEs256JwtTokenAsync(signed_token);

                 if (isTokenValid){
                    Console.WriteLine("Token is valid");
                 } else{
                    Console.WriteLine("Token is not valid");
                 }

               
                }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }


            //   try
            // {
            //     await Client.SendToCustomer(id, "1", "coffee",phoneNumber , paymentMethod, notifyUrl);
               
            //     }
            // catch (Exception ex)
            // {
            //     Console.WriteLine(ex.Message);
            // }



            //   try
            // {
            //     await Client.CheckTransactionStatus(id);
               
            //     }
            // catch (Exception ex)
            // {
            //     Console.WriteLine(ex.Message);
            // }


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

        public string clientReference { get; set; }

        public string receiverAccountNumber { get; set; }

        public string paymentMethod { get; set; }
    }
        }
















    







        
