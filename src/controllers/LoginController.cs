namespace IO.Curity.OAuthAgent.Controllers
{
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.ModelBinding;
    using IO.Curity.OAuthAgent.Entities;

    [Route("oauth-agent")]
    public class LoginController : Controller
    {
        [HttpPost("login/start")]
        public async Task<StartAuthorizationResponse> StartLogin(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] StartAuthorizationParameters parameters)
        {
            return new StartAuthorizationResponse("https://login/example/com/authorize");
        }

        [HttpPost("login/end")]
        public async Task<EndAuthorizationResponse> EndLogin([FromBody] EndAuthorizationRequest request)
        {
            return new EndAuthorizationResponse
            {
                Handled = true,
                IsLoggedIn = true,
                Csrf = "abc"
            };
        }
    }
}
