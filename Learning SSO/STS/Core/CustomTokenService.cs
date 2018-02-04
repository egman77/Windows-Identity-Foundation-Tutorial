using System;
using System.Collections.Generic;
using System.IdentityModel;
using System.IdentityModel.Configuration;
using System.Linq;
using System.Security.Claims;
using System.Web;

namespace STS.Core
{
    /// <summary>
    /// 自定义令牌服务类
    /// </summary>
    public class CustomTokenService : SecurityTokenService
    {
        public CustomTokenService(SecurityTokenServiceConfiguration config)
            : base(config)
        {
        }

        /// <summary>
        /// 获阳输出的声明标识符
        /// </summary>
        /// <param name="principal"></param>
        /// <param name="request"></param>
        /// <param name="scope"></param>
        /// <returns></returns>
        protected override ClaimsIdentity GetOutputClaimsIdentity(ClaimsPrincipal principal, System.IdentityModel.Protocols.WSTrust.RequestSecurityToken request, Scope scope)
        {
            return principal.Identity as ClaimsIdentity;
        }

        /// <summary>
        /// 获得范围 
        /// </summary>
        /// <param name="principal"></param>
        /// <param name="request"></param>
        /// <returns></returns>
        protected override Scope GetScope(ClaimsPrincipal principal, System.IdentityModel.Protocols.WSTrust.RequestSecurityToken request)
        {
            var s = new Scope();
            s.SigningCredentials = SecurityTokenServiceConfiguration.SigningCredentials;
            s.TokenEncryptionRequired = false;
            s.SymmetricKeyEncryptionRequired = false;
            s.ReplyToAddress = request.ReplyTo;
            s.AppliesToAddress = request.AppliesTo.Uri.ToString();
            return s;
        }
    }
}