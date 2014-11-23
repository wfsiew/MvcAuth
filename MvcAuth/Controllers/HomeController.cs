using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.IO;
using System.Net;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Web.Script.Serialization;
using Newtonsoft.Json;
using MvcAuth.Models;

namespace MvcAuth.Controllers
{
    public class HomeController : Controller
    {
        //
        // GET: /Home/

        public ActionResult Index()
        {
            //when the page loads, a random session token needs to be created
            //this will be sent to Google to verify that the data hasn't been tampered with

            //create a random GUID as a token for preventing CSS attacks
            //this only happens if a session doesn't already exist
            if (Session["state"] == null)
                Session["state"] = Guid.NewGuid();

            ViewBag.state = Session["state"];
            return View();
        }

        public ActionResult Callback()
        {
            string code = Request.QueryString["code"];
            string clientid = "767995890535.apps.googleusercontent.com";
            string clientsecret = "MTnxddiDsRnuLJY6Rp9uCoo7";
            string redirecturi = "http://localhost:5850/Home/Callback";
            string granttype = "authorization_code";
            LoginProfile o = new LoginProfile();

            //the state token in the return URL needs to be verified first.
            if (code != null && Session["loggedin"] != "1")
            {
                string state = Request["state"];

                if (state == Convert.ToString(Session["state"]))
                {
                    string url = string.Format("code={0}&client_id={1}&client_secret={2}&redirect_uri={3}&grant_type={4}",
                        code, clientid, clientsecret, redirecturi, granttype);
                    o = PostResult(url);
                    ViewBag.data = "success";
                }

                else
                {
                    ViewBag.data = "Something is wrong in the state";
                }
            }

            else if (Session["loggedin"] == "1")
            {
                ViewBag.data = "Already logged in";
            }

            else
            {
                ViewBag.data = "Not logged in";
            }

            return View(o);
        }

        private LoginProfile PostResult(string e)
        {
            LoginProfile glp = new LoginProfile();

            try
            {
                // variables to store parameter values
                string url = "https://accounts.google.com/o/oauth2/token";

                // creates the post data for the POST request
                string postData = (e);

                // create the POST request
                HttpWebRequest webRequest = (HttpWebRequest)WebRequest.Create(url);
                webRequest.Proxy = null;
                webRequest.Method = "POST";
                webRequest.ContentType = "application/x-www-form-urlencoded";
                webRequest.ContentLength = postData.Length;

                // POST the data
                using (StreamWriter requestWriter2 = new StreamWriter(webRequest.GetRequestStream()))
                {
                    requestWriter2.Write(postData);
                }

                //This actually does the request and gets the response back
                HttpWebResponse resp = (HttpWebResponse)webRequest.GetResponse();

                string googleAuth;

                using (StreamReader responseReader = new StreamReader(webRequest.GetResponse().GetResponseStream()))
                {
                    //dumps the HTML from the response into a string variable
                    googleAuth = responseReader.ReadToEnd();
                }

                LoginInfo gli = JsonConvert.DeserializeObject<LoginInfo>(googleAuth);
                string[] tokenArray = gli.id_token.Split(new Char[] { '.' });

                LoginClaims glc = JsonConvert.DeserializeObject<LoginClaims>(Base64Decode(tokenArray[1]));
                LoginHeader glh = JsonConvert.DeserializeObject<LoginHeader>(Base64Decode(tokenArray[0]));

                //process payload
                LoginClaims glck = JsonConvert.DeserializeObject<LoginClaims>(Base64Decode(tokenArray[1]));

                //we can tell the session that we're logged in
                Session["loggedin"] = "1";

                glp = GetProfile(gli);

                //if (VerifySignature(glh.kid, tokenArray))
                //{
                    
                //}
            }

            catch (Exception ex)
            {
                throw ex;
            }

            return glp;
        }

        private string Base64Decode(string data)
        {
            //add padding with '=' to string to accommodate C# Base64 requirements
            int strlen = data.Length + (4 - (data.Length % 4));
            char pad = '=';
            string datapad;

            if (strlen == (data.Length + 4))
            {
                datapad = data;
            }

            else
            {
                datapad = data.PadRight(strlen, pad);
            }

            try
            {
                System.Text.UTF8Encoding encoder = new System.Text.UTF8Encoding();
                System.Text.Decoder utf8Decode = encoder.GetDecoder();

                // create byte array to store Base64 string
                byte[] todecode_byte = Convert.FromBase64String(datapad);
                int charCount = utf8Decode.GetCharCount(todecode_byte, 0, todecode_byte.Length);
                char[] decoded_char = new char[charCount];
                utf8Decode.GetChars(todecode_byte, 0, todecode_byte.Length, decoded_char, 0);
                string result = new String(decoded_char);
                return result;
            }

            catch (Exception ex)
            {
                throw new Exception("Error in base64Decode: " + ex.Message);
            }
        }

        private LoginProfile GetProfile(LoginInfo gli)
        {
            string url = "https://www.googleapis.com/oauth2/v3/userinfo?access_token=" + gli.access_token;
            WebRequest request = WebRequest.Create(url);
            request.Proxy = null;
            WebResponse response = request.GetResponse();
            Stream data = response.GetResponseStream();

            string v;

            using (StreamReader sr = new StreamReader(data))
            {
                v = sr.ReadToEnd();
            }

            LoginProfile glp = JsonConvert.DeserializeObject<LoginProfile>(v);

            return glp;
        }

        private void CacheCertificate(string kid)
        {
            //if the certificate ID doesn't already exist as a local certificate file, download it from Google
            if (!System.IO.File.Exists(@"C:\certs" + kid + ".cer"))
            {
                //pull JSON certificate data from Google
                string url = "https://www.googleapis.com/oauth2/v1/certs";
                WebRequest request = WebRequest.Create(url);
                request.Proxy = null;
                WebResponse response = request.GetResponse();
                Stream certdata = response.GetResponseStream();

                string certs;

                using (StreamReader sr = new StreamReader(certdata))
                {
                    certs = sr.ReadToEnd();
                }

                //certs are returned as a JSON object

                //convert the JSON object into a dictionary
                Dictionary<dynamic, dynamic> cts = JsonConvert.DeserializeObject<Dictionary<dynamic, dynamic>>(certs);

                string b64 = cts[kid];

                //write the certificate to a file with the .cer extension, which identifies it as a digital certificate
                //these are stored outside the web server filespace
                System.IO.File.WriteAllText(@"C:\certs" + kid + ".cer", b64);
            }
        }

        private bool VerifySignature(string kid, string[] jwt)
        {
            //this will return TRUE if the signature is valid or FALSE if it is invalid
            //if the signature is invalid, we must not accept the user's login information!

            //by default, the signature isn't valid, just as a precaution
            bool verified = false;

            //before we do anything else, we need to locally cache Google's public certificate, if it isn't already
            CacheCertificate(kid);

            //pull out the different elements from the original JWT provided by Google
            string toVerify = jwt[0] + "." + jwt[1];
            string signature = jwt[2];

            byte[] sig = Base64urldecode(signature);

            //the header and payload need to be converted to a byte array
            byte[] data = Encoding.UTF8.GetBytes(toVerify);

            //create an X509 cert from the google certificate in local cache
            X509Certificate gcert = X509Certificate.CreateFromCertFile(@"C:\certs" + kid + ".cer");

            //we need to use the new X509Certificate2 subclass in order to pull the public key from the certificate
            X509Certificate2 gcert2 = new X509Certificate2(gcert);

            using (var rsa = (RSACryptoServiceProvider)gcert2.PublicKey.Key)
            {
                //create a new byte array that contains a SHA256 hash of the JSON header and payload
                byte[] hash;
                using (SHA256 sha256 = SHA256.Create())
                {
                    hash = sha256.ComputeHash(data);
                }

                string h = UTF8Encoding.UTF8.GetString(hash);

                //Create an RSAPKCS1SignatureDeformatter object and pass it the   
                //RSACryptoServiceProvider to transfer the key information.
                RSAPKCS1SignatureDeformatter RSADeformatter = new RSAPKCS1SignatureDeformatter(rsa);
                RSADeformatter.SetHashAlgorithm("SHA256");

                //Verify the hash and return the appropriate bool value
                if (RSADeformatter.VerifySignature(hash, sig))
                {
                    verified = true;
                }

                else
                {
                    verified = false;
                }
            }

            return verified;
        }

        private byte[] Base64urldecode(string arg)
        {
            //this swaps out the characters in Base64Url encoding for valid Base64 syntax
            //C# can't decode Base64 without doing this first
            arg = arg.Replace('-', '+');
            arg = arg.Replace('_', '/');

            int strlen = arg.Length + (4 - (arg.Length % 4));
            char pad = '=';

            if (strlen != (arg.Length + 4))
            {
                arg = arg.PadRight(strlen, pad);
            }

            //return the Base64 decoded data as a byte array, since that's what we need for RSA
            byte[] arg2 = Convert.FromBase64String(arg);

            return arg2;
        }
    }
}
