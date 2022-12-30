namespace IO.Curity.OAuthAgent.AddControllers
{
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using IO.Curity.OAuthAgent.Entities;

    [Route("oauth-agent")]
    public class LogoutController : Controller
    {
        [HttpPost("logout")]
        public async Task<LogoutUserResponse> Logout()
        {
            return new LogoutUserResponse("https://login/example/com/end-session");
        }
    }
}
