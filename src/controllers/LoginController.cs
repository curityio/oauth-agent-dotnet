namespace IO.Curity.OAuthAgent.Controllers
{
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.ModelBinding;
    using IO.Curity.OAuthAgent.Entities;
    using IO.Curity.OAuthAgent.Utilities;

    [Route("oauth-agent")]
    public class LoginController : Controller
    {
        private readonly LoginHandler loginHandler;
        private readonly RequestValidator requestValidator;
        
        public LoginController(LoginHandler loginHandler, RequestValidator requestValidator)
        {
            this.loginHandler = loginHandler;
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

            var authorizationRequestData = this.loginHandler.CreateAuthorizationRequest(parameters);
        
            return new StartAuthorizationResponse(authorizationRequestData.AuthorizationRequestUrl);
        }

        /*
         * Handle OpenID Connect front channel responses, redeem the code for tokens, and write cookies
         */
        [HttpPost("login/end")]
        public async Task<EndAuthorizationResponse> EndLogin([FromBody] EndAuthorizationRequest request)
        {
            this.requestValidator.ValidateRequest(this.HttpContext.Request, new RequestValidationOptions{RequireCsrfHeader = false});

            return new EndAuthorizationResponse
            {
                Handled = false,
                IsLoggedIn = false,
                Csrf = ""
            };
        }
    }
}
