namespace IO.Curity.OAuthAgent.Controllers
{
    using System.Text;
    using System.Web;
    using Microsoft.AspNetCore.Mvc;
    using IO.Curity.OAuthAgent.Entities;
    using IO.Curity.OAuthAgent.Exceptions;
    using IO.Curity.OAuthAgent.Utilities;

    [Route("oauth-agent")]
    public class LogoutController : Controller
    {
        private readonly OAuthAgentConfiguration configuration;
        
        private readonly CookieManager cookieManager;

        private readonly RequestValidator requestValidator;

        public LogoutController(
            OAuthAgentConfiguration configuration,
            CookieManager cookieManager,
            RequestValidator requestValidator)
        {
            this.configuration = configuration;
            this.cookieManager = cookieManager;
            this.requestValidator = requestValidator;
        }
        
        [HttpPost("logout")]
        public LogoutUserResponse Logout()
        {
            // First check that the web origin and a CSRF token are provided
            this.requestValidator.ValidateRequest(this.HttpContext.Request, new RequestValidationOptions());

            // Next ensure that we have valid cookies
            var accessToken = this.GetAccessTokenFromCookie();
            if (string.IsNullOrWhiteSpace(accessToken))
            {
                throw new InvalidCookieException("No valid access cookie was supplied in a call to logout");
            }

            // Next expire all cookies
            var cookies = this.cookieManager.ExpireAllCookies();
            cookies.ForEach(cookie => {

                var (name, value, options) = cookie;
                this.Response.Cookies.Append(name, value, options);
            });

            // Return the logout URL to the SPA
            var url = new StringBuilder();
            url.Append(this.configuration.LogoutEndpoint);
            url.Append($"?client_id={HttpUtility.UrlEncode(this.configuration.ClientID)}");
            url.Append($"&post_logout_redirect_uri={HttpUtility.UrlEncode(this.configuration.PostLogoutRedirectUri)}");
            return new LogoutUserResponse(url.ToString());
        }

        /*
         * Return the access token if received
         */
        private string GetAccessTokenFromCookie()
        {
            if (this.Request.Cookies != null)
            {
                var accessCookieName = this.cookieManager.GetCookieName(CookieManager.CookieName.access);
                var accessCookie = this.Request.Cookies[accessCookieName];
                return this.cookieManager.DecryptCookieSafe(CookieManager.CookieName.access, accessCookie);
            }

            return "";
        }
    }
}
