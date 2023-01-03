namespace IO.Curity.OAuthAgent.Controllers
{
    using System;
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
            AuthorizationServerClient authorizationServerClient,
            IdTokenValidator idTokenValidator,
            RequestValidator requestValidator)
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
            this.requestValidator.ValidateRequest(this.HttpContext.Request, new RequestValidationOptions{RequireCsrfHeader = false});

            // Produce the authentication request URL for the SPA
            var data = this.loginHandler.CreateAuthorizationRequest(parameters);
            
            // Store a temp login cookie
            var (name, value, options) = this.cookieManager.CreateTempLoginStateCookie(data.State, data.CodeVerifier);
            this.Response.Cookies.Append(name, value, options);
        
            return new StartAuthorizationResponse(data.AuthorizationRequestUrl);
        }

        /*
         * Handle OpenID Connect front channel responses, redeem the code for tokens, and write cookies
         */
        [HttpPost("login/end")]
        public async Task<EndAuthorizationResponse> EndLogin([FromBody] EndAuthorizationRequest request)
        {
            // First check that the web origin is allowed
            this.requestValidator.ValidateRequest(this.HttpContext.Request, new RequestValidationOptions{RequireCsrfHeader = false});

            // Next process query parameters
            var queryParams = this.loginHandler.HandleAuthorizationResponse(request.PageUrl);
            var isOAuthResponse = !string.IsNullOrWhiteSpace(queryParams.Code) && !string.IsNullOrWhiteSpace(queryParams.State);

            // Set the login state from existing cookies
            var csrfToken = this.GetCsrfTokenFromCookie();
            var isLoggedIn = !string.IsNullOrWhiteSpace(csrfToken);

            if (isOAuthResponse)
            {
                // Decrypt the temporary login cookie and verify the state response parameter
                
                var loginData = this.GetLoginDataFromCookie();
                if (loginData?.State != queryParams.State)
                {
                    throw new InvalidStateException();
                }

                // The CSRF token is stored in memory and sent as a request header from each browser tab
                // Avoid generating a new one unless needed, to prevent application problems
                if (string.IsNullOrWhiteSpace(csrfToken))
                {
                    csrfToken = RandomStringGenerator.CreateCsrfToken();
                }

                // Redeem the code for tokens, then validate the ID token
                var tokenResponse = await this.authorizationServerClient.RedeemCodeForTokens(queryParams.Code, loginData.CodeVerifier);
                this.idTokenValidator.Validate(tokenResponse.IdToken);

                // Write tokens containing cookies
                var cookies = this.cookieManager.CreateCookies(tokenResponse, csrfToken);
                cookies.ForEach(cookie => {

                    var (name, value, options) = cookie;
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

        /*
         * Return data from the CSRF token if it exists
         */
        private string GetCsrfTokenFromCookie()
        {
            if (this.Request.Cookies != null)
            {
                var csrfCookieName = this.cookieManager.GetCookieName(CookieManager.CookieName.csrf);
                var csrfCookie = this.Request.Cookies[csrfCookieName];
                return this.cookieManager.DecryptCsrfCookie(csrfCookie);
            }

            return "";
        }

        /*
         * Return data from the login cookie if it exists
         */
        private TempLoginData GetLoginDataFromCookie()
        {
            if (this.Request.Cookies != null)
            {
                var loginCookieName = this.cookieManager.GetCookieName(CookieManager.CookieName.login);
                var tempLoginCookie = this.Request.Cookies[loginCookieName];
                return this.cookieManager.DecryptLoginStateCookie(tempLoginCookie);
            }

            return null;
        }
    }
}
