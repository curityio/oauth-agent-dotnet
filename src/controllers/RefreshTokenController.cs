namespace IO.Curity.OAuthAgent.Controllers
{
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using IO.Curity.OAuthAgent.Exceptions;
    using IO.Curity.OAuthAgent.Utilities;

    [Route("oauth-agent")]
    public class RefreshTokenController : Controller
    {
        private readonly OAuthAgentConfiguration configuration;
        
        private readonly CookieManager cookieManager;

        private readonly AuthorizationServerClient authorizationServerClient;

        private readonly IdTokenValidator idTokenValidator;

        private readonly RequestValidator requestValidator;

        public RefreshTokenController(
            OAuthAgentConfiguration configuration,
            CookieManager cookieManager,
            AuthorizationServerClient authorizationServerClient,
            IdTokenValidator idTokenValidator,
            RequestValidator requestValidator)
        {
            this.configuration = configuration;
            this.cookieManager = cookieManager;
            this.authorizationServerClient = authorizationServerClient;
            this.idTokenValidator = idTokenValidator;
            this.requestValidator = requestValidator;
        }

        [HttpPost("refresh")]
        public async Task RefreshToken()
        {
            // First check that the web origin and a CSRF token are provided
            this.requestValidator.ValidateRequest(this.HttpContext.Request, new RequestValidationOptions());

            // Next get the refresh token
            var refreshToken = this.GetRefreshTokenFromCookie();
            if (string.IsNullOrWhiteSpace(refreshToken))
            {
                throw new InvalidCookieException("No valid refresh cookie was supplied in a call to refresh token");
            }

            // Call the authorization server and return the data
            var tokenResponse = await this.authorizationServerClient.RefreshAccessToken(refreshToken);
            if (!string.IsNullOrWhiteSpace(tokenResponse.IdToken))
            {
                idTokenValidator.Validate(tokenResponse.IdToken);
            }

            // Write updated cookies
            var cookies = this.cookieManager.RefreshCookies(tokenResponse);
            cookies.ForEach(cookie => {

                var (name, value, options) = cookie;
                this.Response.Cookies.Append(name, value, options);
            });
        }

        /*
         * Return the refresh token if received
         */
        private string GetRefreshTokenFromCookie()
        {
            if (this.Request.Cookies != null)
            {
                var refreshCookieName = this.cookieManager.GetCookieName(CookieManager.CookieName.refresh);
                var refreshCookie = this.Request.Cookies[refreshCookieName];
                return this.cookieManager.DecryptCookieSafe(CookieManager.CookieName.refresh, refreshCookie);
            }

            return "";
        }
    }
}
