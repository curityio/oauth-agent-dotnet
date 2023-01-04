namespace IO.Curity.OAuthAgent.Controllers
{
    using System.Collections.Generic;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using IO.Curity.OAuthAgent.Exceptions;
    using IO.Curity.OAuthAgent.Utilities;

    [Route("oauth-agent")]
    public class UserInfoController : Controller
    {
        private readonly OAuthAgentConfiguration configuration;
        
        private readonly CookieManager cookieManager;

        private readonly AuthorizationServerClient authorizationServerClient;

        private readonly RequestValidator requestValidator;

        public UserInfoController(
            OAuthAgentConfiguration configuration,
            CookieManager cookieManager,
            AuthorizationServerClient authorizationServerClient,
            RequestValidator requestValidator)
        {
            this.configuration = configuration;
            this.cookieManager = cookieManager;
            this.authorizationServerClient = authorizationServerClient;
            this.requestValidator = requestValidator;
        }

        /*
         * Return data from the user info endpoint to the SPA
         */
        [HttpGet("userInfo")]
        public async Task<IDictionary<string, object>> GetUserInfo()
        {
            // In CORS setups, validate the web origin, whereas in same site deployments the origin header is not sent
            var options = new RequestValidationOptions
            {
                RequireTrustedOrigin = this.configuration.CorsEnabled,
                RequireCsrfHeader = false
            };
            this.requestValidator.ValidateRequest(this.HttpContext.Request, options);

            // Next get the access token
            var accessToken = this.GetAccessTokenFromCookie();
            if (string.IsNullOrWhiteSpace(accessToken))
            {
                throw new InvalidCookieException("No valid access cookie was supplied in a call to get user info");
            }

            // Call the authorization server and return the data
            return await this.authorizationServerClient.GetUserInfo(accessToken);
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