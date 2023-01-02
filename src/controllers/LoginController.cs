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
            this.requestValidator.ValidateRequest(this.HttpContext.Request, new RequestValidationOptions{RequireCsrfHeader = false});

            var data = this.loginHandler.CreateAuthorizationRequest(parameters);
            
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
            this.requestValidator.ValidateRequest(this.HttpContext.Request, new RequestValidationOptions{RequireCsrfHeader = false});

            var queryParams = await this.loginHandler.HandleAuthorizationResponse(request.PageUrl);
            var isOAuthResponse = !string.IsNullOrWhiteSpace(queryParams.Code) && !string.IsNullOrWhiteSpace(queryParams.State);
            var isLoggedIn = false;

            if (isOAuthResponse)
            {
                var loginCookieName = this.cookieManager.GetCookieName(CookieManager.CookieName.login);
                var tempLoginCookie = this.Request.Cookies[loginCookieName];
                var loginData = this.cookieManager.ReadStoredLoginStateCookie(tempLoginCookie);
                
                if (loginData.State != queryParams.State)
                {
                    throw new InvalidStateException();
                }

                var tokenResponse = await this.authorizationServerClient.RedeemCodeForTokens(queryParams.Code, loginData.CodeVerifier);
                this.idTokenValidator.Validate(tokenResponse.IdToken);

                var cookies = this.cookieManager.CreateCookies(tokenResponse);
                cookies.ForEach(cookie => {

                    var (name, value, options) = cookie;
                    this.Response.Cookies.Append(name, value, options);
                });

                isLoggedIn = true;
            }

            return new EndAuthorizationResponse
            {
                Handled = isOAuthResponse,
                IsLoggedIn = isLoggedIn,
                Csrf = ""
            };
        }
    }
}
