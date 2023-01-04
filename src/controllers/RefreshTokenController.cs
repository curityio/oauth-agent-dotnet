namespace IO.Curity.OAuthAgent.Controllers
{
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using IO.Curity.OAuthAgent.Exceptions;

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
            RequestValidator requestValidator,
            AuthorizationServerClient authorizationServerClient,
            IdTokenValidator idTokenValidator)
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
            var csrfToken = this.cookieManager.GetCookieSafe(this.Request, CookieManager.CookieName.csrf);
            this.requestValidator.ValidateRequest(this.HttpContext.Request, csrfToken: csrfToken);

            // Next get the refresh token
            var refreshToken = this.cookieManager.GetCookieSafe(this.Request, CookieManager.CookieName.refresh);
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

            // Write updated cookies to response headers
            var cookies = this.cookieManager.RefreshCookies(tokenResponse);
            cookies.ForEach(cookie => {

                var (name, value, options) = cookie;
                this.Response.Cookies.Append(name, value, options);
            });

            // Indicate no body content
            this.Response.StatusCode = 204;
        }
    }
}
