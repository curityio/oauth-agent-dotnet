namespace IO.Curity.OAuthAgent.Controllers
{
    using System.Collections.Generic;
    using System.IdentityModel.Tokens.Jwt;
    using System.Linq;
    using Microsoft.AspNetCore.Mvc;
    using IO.Curity.OAuthAgent.Exceptions;
    using IO.Curity.OAuthAgent.Utilities;

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
         * Return claims from th ID token to the SPA
         */
        [HttpGet("claims")]
        public IDictionary<string, object> GetClaims()
        {
            // In CORS setups, validate the web origin, whereas in same site deployments the origin header is not sent
            var options = new RequestValidationOptions
            {
                RequireTrustedOrigin = this.configuration.CorsEnabled,
                RequireCsrfHeader = false
            };
            this.requestValidator.ValidateRequest(this.HttpContext.Request, options);

            // Next get the ID token
            var idToken = this.GetIdTokenFromCookie();
            if (string.IsNullOrWhiteSpace(idToken))
            {
                throw new InvalidCookieException("No valid ID cookie was supplied in a call to get claims");
            }

            // Decode it and return its claims
            var token = new JwtSecurityToken(idToken);
            var result = new Dictionary<string, object>();
            token.Claims.ToList().ForEach(c => result.Add(c.Type, c.Value));
            return result;
        } 

        /*
         * Return the ID token if received
         */
        private string GetIdTokenFromCookie()
        {
            if (this.Request.Cookies != null)
            {
                var idCookieName = this.cookieManager.GetCookieName(CookieManager.CookieName.id);
                var idCookie = this.Request.Cookies[idCookieName];
                return this.cookieManager.DecryptCookieSafe(CookieManager.CookieName.id, idCookie);
            }

            return "";
        }
    }
}