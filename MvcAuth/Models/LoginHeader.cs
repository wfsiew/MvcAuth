using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace MvcAuth.Models
{
    public class LoginHeader
    {
        public string alg { get; set; }
        public string kid { get; set; }
    }
}