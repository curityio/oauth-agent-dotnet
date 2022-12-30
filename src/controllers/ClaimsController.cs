namespace IO.Curity.OAuthAgent.AddControllers
{
    using System.Collections.Generic;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;

    [Route("oauth-agent")]
    public class ClaimsController : Controller
    {
        [HttpGet("claims")]
        public async Task<IDictionary<string, string> > GetClaims()
        {
            var data = new Dictionary<string, string>();
            data.Add("Claims", "1");
            return data;
        }
    }
}