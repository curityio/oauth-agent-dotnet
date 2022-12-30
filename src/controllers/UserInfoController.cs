namespace IO.Curity.OAuthAgent.AddControllers
{
    using System.Collections.Generic;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;

    [Route("oauth-agent")]
    public class UserInfoController : Controller
    {
        [HttpGet("userInfo")]
        public async Task<IDictionary<string, string> > GetClaims()
        {
            var data = new Dictionary<string, string>();
            data.Add("UserInfo", "1");
            return data;
        }
    }
}