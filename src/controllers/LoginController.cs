namespace IO.Curity.OAuthAgent.Controllers
{
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.ModelBinding;
    using IO.Curity.OAuthAgent.Entities;
    using IO.Curity.OAuthAgent.Exceptions;
    using IO.Curity.OAuthAgent.Utilities;

    [Route("oauth-agent")]
    public class LoginController : Controller
    {
        private readonly LoginHandler loginHandler;
        private readonly CookieManager cookieManager;
        private readonly AuthorizationServerClient authorizationServerClient;
        private readonly IdTokenValidator idTokenValidator;
        private readonly RequestValidator requestValidator;

        public LoginController(
            LoginHandler loginHandler,
            CookieManager cookieManager,
            RequestValidator requestValidator,
            AuthorizationServerClient authorizationServerClient,
            IdTokenValidator idTokenValidator)
        {
            this.loginHandler = loginHandler;
            this.cookieManager = cookieManager;
            this.authorizationServerClient = authorizationServerClient;
            this.idTokenValidator = idTokenValidator;
            this.requestValidator = requestValidator;
        }

        /*
         * Create the OpenID Connect request URL and set temporary cookies with the state and code verifier
         */
        [HttpPost("login/start")]
        public StartAuthorizationResponse StartLogin(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] StartAuthorizationParameters parameters)
        {
            // First check that the web origin is allowed
            this.requestValidator.ValidateRequest(this.HttpContext.Request, requireCsrfHeader: false);

            // Produce the authentication request URL for the SPA
            var data = this.loginHandler.CreateAuthorizationRequest(parameters);
            
            // Store a temp login cookie
            var (name, value, options) = this.cookieManager.CreateTempLoginStateCookie(data.State, data.CodeVerifier);
            this.Response.Cookies.Append(name, value, options);
        
            // Give the URL to the SPA, which manages its own redirect
            return new StartAuthorizationResponse(data.AuthorizationRequestUrl);
        }

        /*
         * Handle OpenID Connect front channel responses, redeem the code for tokens, and write cookies
         */
        [HttpPost("login/end")]
        public async Task<EndAuthorizationResponse> EndLogin(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] EndAuthorizationRequest data)
        {
            // First check that the web origin is allowed
            this.requestValidator.ValidateRequest(this.HttpContext.Request, requireCsrfHeader: false);
            
            // Next process the payload
            if (data == null)
            {
                throw new InvalidRequestException("Invalid request data was received");
            }
            var queryParams = this.loginHandler.HandleAuthorizationResponse(data.PageUrl);
            var isOAuthResponse = !string.IsNullOrWhiteSpace(queryParams.Code) && !string.IsNullOrWhiteSpace(queryParams.State);

            // Set the login state from existing cookies
            var csrfToken = this.cookieManager.GetCookieSafe(this.Request, CookieManager.CookieName.csrf);
            var isLoggedIn = !string.IsNullOrWhiteSpace(csrfToken);

            if (isOAuthResponse)
            {
                // Decrypt the temporary login cookie
                var loginData = this.cookieManager.GetLoginStateCookieSafe(this.Request);
                if (loginData == null)
                {
                    throw new InvalidCookieException("No valid login cookie was supplied in a call to end login");
                }

                //  Verify the state response parameter
                if (loginData.State != queryParams.State)
                {
                    throw new InvalidStateException();
                }

                // The CSRF token is stored in memory and sent as a request header from each browser tab
                // In the event of logins being triggered from two browser tabs, return the existing value
                if (string.IsNullOrWhiteSpace(csrfToken))
                {
                    csrfToken = RandomStringGenerator.CreateCsrfToken();
                }

                // Redeem the code for tokens, then validate the ID token
                var tokenResponse = await this.authorizationServerClient.RedeemCodeForTokens(queryParams.Code, loginData.CodeVerifier);
                this.idTokenValidator.Validate(tokenResponse.IdToken);

                // Issue cookies containing tokens, and cookies are small when opaque tokens are used
                var cookies = this.cookieManager.CreateCookies(tokenResponse, csrfToken);
                cookies.ForEach(cookie => {

                    var (name, value, options) = cookie;
                    this.Response.Cookies.Delete(name);
                    this.Response.Cookies.Append(name, value, options);
                });

                isLoggedIn = true;
            }

            // Give the SPA the fields it needs
            return new EndAuthorizationResponse
            {
                Handled = isOAuthResponse,
                IsLoggedIn = isLoggedIn,
                Csrf = csrfToken,
            };
        }
    }
}
