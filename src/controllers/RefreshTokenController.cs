namespace IO.Curity.OAuthAgent.AddControllers
{
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;

    [Route("oauth-agent")]
    public class RefreshTokenController : Controller
    {
        [HttpPost("refresh")]
        public async Task RefreshToken()
        {
        }
    }
}
