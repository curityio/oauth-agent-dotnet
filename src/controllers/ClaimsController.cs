namespace IO.Curity.OAuthAgent.Controllers
{
    using System.IdentityModel.Tokens.Jwt;
    using Microsoft.AspNetCore.Mvc;
    using IO.Curity.OAuthAgent.Exceptions;

    [Route("oauth-agent")]
    public class ClaimsController : Controller
    {
        private readonly OAuthAgentConfiguration configuration;
        
        private readonly CookieManager cookieManager;

        private readonly RequestValidator requestValidator;

        public ClaimsController(
            OAuthAgentConfiguration configuration,
            CookieManager cookieManager,
            RequestValidator requestValidator)
        {
            this.configuration = configuration;
            this.cookieManager = cookieManager;
            this.requestValidator = requestValidator;
        }

        /*
         * Return claims from the ID token to the SPA
         */
        [HttpGet("claims")]
        public ContentResult GetClaims()
        {
            // In CORS setups, validate the web origin, whereas in same site deployments the origin header is not sent
            this.requestValidator.ValidateRequest(
                this.HttpContext.Request,
                requireTrustedOrigin: this.configuration.CorsEnabled,
                requireCsrfHeader: false);

            // Next get the ID token
            var idToken = this.cookieManager.GetCookieSafe(this.Request, CookieManager.CookieName.id);
            if (string.IsNullOrWhiteSpace(idToken))
            {
                throw new InvalidCookieException("No valid ID cookie was supplied in a call to get claims");
            }

            // Decode it and return its claims
            var token = new JwtSecurityToken(idToken);
            var json = token.Payload.SerializeToJson();
            return Content(json, "application/json");
        }
    }
}