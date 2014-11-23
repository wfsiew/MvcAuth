using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace MvcAuth.Models
{
    public class LoginClaims
    {
        public string aud { get; set; }
        public string email_verified { get; set; }
        public string at_hash { get; set; }
        public string azp { get; set; }
        public string email { get; set; }
        public string sub { get; set; }
        public string iss { get; set; }
        public int exp { get; set; }
        public string iat { get; set; }
    }
}