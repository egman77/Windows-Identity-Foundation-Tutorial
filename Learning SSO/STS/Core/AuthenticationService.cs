using STS.Models;
using System;
using System.Collections.Generic;
using System.IdentityModel.Configuration;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Web;
using System.Web.Mvc;

namespace STS.Core
{
    /// <summary>
    /// 验证服务类
    /// </summary>
    public class AuthenticationService
    {

        /// <summary>
        /// 注销
        /// </summary>
        public const string SignOutLiteral = "wsignout1.0";
        public const string SignOutCleanupLiteral = "wsignoutcleanup1.0";
        /// <summary>
        /// 登录
        /// </summary>
        public const string SignInLiteral = "wsignin1.0";
        public const string RealmLiteral = "wtrealm";
        public const string ReplyLiteral = "wreply";

        
        
        /// <summary>
        /// 加载证书(不需要安装到系统上)
        /// </summary>
        /// <returns></returns>
        X509Certificate2 LoadCertificate()
        {
            return new X509Certificate2(
                string.Format(@"{0}\bin\Certificate.pfx", AppDomain.CurrentDomain.BaseDirectory), "");
        }

        /// <summary>
        /// 第一次登录前,登录验证
        /// User hadn't logged in before, so set an authentication cookie in the WSFed response for this domain
        /// </summary>
        private IPrincipal AuthenticateAndCreateCookie(string relyingPartyUrl)
        {
            var user = new ClaimsIdentity(AuthenticationTypes.Federation);
            //模拟,只用test用户名
            user.AddClaim(new Claim(ClaimTypes.Name, "test"));
            user.AddClaim(new Claim(ClaimTypes.Uri, relyingPartyUrl));
            return SaveToCookie(user);
        }

        /// <summary>
        /// 已登录后,再次验证
        /// The user had already signed in from one domain, sign the user in from the previously set cookie
        /// </summary>
        private IPrincipal PreviouslyAuthenticated(string relyingPartyUrl)
        {
            var user = (ClaimsIdentity)HttpContext.Current.User.Identity;
            user.AddClaim(new Claim(ClaimTypes.Uri, relyingPartyUrl));
            return SaveToCookie(user);
        }

        /// <summary>
        /// 保存到客户端Cookie中
        /// Save user state to cookie
        /// </summary>
        /// <param name="user">User to save to cookie</param>
        /// <returns></returns>
        private static ClaimsPrincipal SaveToCookie(ClaimsIdentity user)
        {
            //创建声明主角
            var claimsPrincipal = new ClaimsPrincipal(user);
            //创建会话安全令牌
            var sessionSecurityToken = new SessionSecurityToken(claimsPrincipal, TimeSpan.FromDays(365));
            //写入会话安全令牌
            FederatedAuthentication.SessionAuthenticationModule.WriteSessionTokenToCookie(sessionSecurityToken);
            return claimsPrincipal;
        }

        /// <summary>
        /// 计算出联合验证是功能方法
        /// Figure out, if the user wants to sign in or sign out, and do the correct path based on that
        /// </summary>
        /// <returns></returns>
        public ActionResult ProcessRequest()
        {
            // Pull the request apart
            var message = WSFederationMessage.CreateFromUri(HttpContext.Current.Request.Url);

            //依赖方的地址
            // Get the relying party url
            var relyingPartyUrl = HttpContext.Current.Request.UrlReferrer.ToString();

            //需要重定向到的地址
            // Get reply to address
            var reply = message.GetParameter(ReplyLiteral);

            //从消息头得到操作类型
            // Sign out, if the action or wa-parameter is "wsignout1.0", and sign in otherwise
            return message.Action == SignOutLiteral ? SignOut(reply, relyingPartyUrl) : SignIn(relyingPartyUrl);
        }

        /// <summary>
        /// 注销
        /// Find out which realms the user is signed in - sign them out from all of them, and return to @replyTo
        /// </summary>
        /// <param name="replyTo">当注销后,要重定向的地址 Redirect to this address after signout is done</param>
        /// <param name="relyingPartyUrl">依赖方的URL</param>
        /// <returns>A bit of html, which renders images with signout urls for all domains.</returns>
        private ActionResult SignOut(string replyTo, string relyingPartyUrl)
        {
            //注销
            // First, remove the session authentication cookie for the STS
            FederatedAuthentication.SessionAuthenticationModule.SignOut();

            //取声明标识符
            var ci = (ClaimsIdentity)HttpContext.Current.User.Identity;

            //找到注销的声明标识符
            // Get all urls where the user has signed in previously, and make them into a list of strings with the format "{url}?wa=wsignoutcleanup1.0"
            var logoutUrls = ci.FindAll(i => i.Type == ClaimTypes.Uri).Select(i => string.Format("{0}?wa={1}", i.Value, SignOutCleanupLiteral)).ToList();

            //构造视图模型
            // Construct a viewmodel from the logout urls and replyto address
            var model = new LogoutViewModel { LogoutUrls = logoutUrls, ReplyTo = replyTo };

            //
            // Add relying party url if it isn't in there, because in some cases, a client might call signout even though the local STS cookie has expired 
            var relyingPartyUrlCleanup = string.Format("{0}?wa={1}", relyingPartyUrl, SignOutCleanupLiteral);

            //如果不包含,则加入新构造的视图模型 
            if (!logoutUrls.Contains(relyingPartyUrlCleanup))
                logoutUrls.Add(relyingPartyUrlCleanup);

            //构造返回数据
            // Build a viewresult object and return that
            var viewResult = new ViewResult
            {
                ViewName = "~/Views/Shared/Logout.cshtml",
                ViewData = new ViewDataDictionary(model)
            };
            return viewResult;
        }


        /// <summary>
        /// 登录
        /// </summary>
        /// <param name="replyToAddress">要回复的地址</param>
        /// <returns></returns>
        private ActionResult SignIn(string replyToAddress)
        {
            //取用户声明主角,要区分 已登录和第一次登录
            var user = HttpContext.Current.User.Identity.IsAuthenticated ? PreviouslyAuthenticated(replyToAddress) : AuthenticateAndCreateCookie(replyToAddress);
            //取令牌服务配置类(有缓存吗?)
            var config = new SecurityTokenServiceConfiguration("http://sts.local", new X509SigningCredentials(LoadCertificate()));

            //联合被动令牌服务操作, 处理请求
            FederatedPassiveSecurityTokenServiceOperations.ProcessRequest(HttpContext.Current.Request, (ClaimsPrincipal)user, new CustomTokenService(config), HttpContext.Current.Response);
            //设置http状态
            return new HttpStatusCodeResult(HttpStatusCode.OK);
        }
    }
}