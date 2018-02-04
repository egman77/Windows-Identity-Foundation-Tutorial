using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Web;
using System.Web.Mvc;
using System.IdentityModel.Services;
using System.Security.Claims;
using System.IdentityModel.Configuration;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using STS.Core;
using System.Security.Principal;


namespace STS.Controllers
{
  
    /// <summary>
    /// 验证控制器
    /// Entry point into our STS
    /// </summary>
    public class AuthenticationController : Controller
    {
        [Route("")]
        public ActionResult Index()
        {
            var authenticator = new AuthenticationService();
            ActionResult result=null;
            try
            {
                result = authenticator.ProcessRequest();
            }
            catch (Exception ex)
            {
                return View("error",ex);
               // throw;
            }

            return result;
        }
	}
}