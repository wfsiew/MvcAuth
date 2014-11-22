using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace MvcAuth.Models
{
    public class LoginClaims
    {
        public string aud, iss, email_verified, at_hash, azp, email, sub;
        public int exp, iat;
    }
}