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
        private readonly RequestValidator requestValidator;
        
        public LoginController(RequestValidator requestValidator)
        {
            this.requestValidator = requestValidator;
        }


        [HttpPost("login/start")]
        public async Task<StartAuthorizationResponse> StartLogin(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] StartAuthorizationParameters parameters)
        {
            this.requestValidator.ValidateRequest(this.HttpContext.Request, new RequestValidationOptions{RequireCsrfHeader = false});
        
            return new StartAuthorizationResponse("https://login/example/com/authorize");
        }

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
