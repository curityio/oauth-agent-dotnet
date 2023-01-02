namespace IO.Curity.OAuthAgent
{
    using System.Text;
    using System.Web;
    using IO.Curity.OAuthAgent.Entities;
    using IO.Curity.OAuthAgent.Utilities;

    public class LoginHandler
    {
        private readonly OAuthAgentConfiguration configuration;
        
        public LoginHandler(OAuthAgentConfiguration configuration)
        {
            this.configuration = configuration;
        }

        public AuthorizationRequestData CreateAuthorizationRequest(StartAuthorizationParameters parameters)
        {
            var state = RandomStringGenerator.CreateState();
            var (codeVerifier, codeChallenge) = RandomStringGenerator.CreateCodeVerifier();

            var url = new StringBuilder();
            url.Append(this.configuration.AuthorizeEndpoint);
            url.Append($"?client_id={HttpUtility.UrlEncode(this.configuration.ClientID)}");
            url.Append($"?redirect_uri={HttpUtility.UrlEncode(this.configuration.RedirectUri)}");
            url.Append("&response_type=code");
            url.Append($"&state=${HttpUtility.UrlEncode(state)}");
            url.Append($"&code_challenge=${HttpUtility.UrlEncode(codeChallenge)}");
            url.Append("&code_challenge_method=S256");

            if (this.configuration.Scope != null)
            {
                url.Append($"&scope=${HttpUtility.UrlEncode(configuration.Scope)}");
            }

            parameters?.ExtraParams?.ForEach(param => {

                url.Append($"&{param.Key}=${HttpUtility.UrlEncode(param.Value)}");
            });
        
            return new AuthorizationRequestData(url.ToString(), codeVerifier, state);
        }
    }
}
