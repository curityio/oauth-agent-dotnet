namespace IO.Curity.OAuthAgent
{
    using System.Collections.Generic;
    using System.Net.Http;
    using System.Net.Http.Json;
    using System.Threading.Tasks;
    using IO.Curity.OAuthAgent.Entities;
    using IO.Curity.OAuthAgent.Exceptions;

    public class AuthorizationServerClient
    {
        private readonly OAuthAgentConfiguration configuration;

        public AuthorizationServerClient(OAuthAgentConfiguration configuration)
        {
            this.configuration = configuration;
        }

        public async Task<TokenResponse> RedeemCodeForTokens(string code, string codeVerifier)
        {
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("accept", "application/json");
                var data = new[]
                {
                    new KeyValuePair<string, string>("client_id", this.configuration.ClientID),
                    new KeyValuePair<string, string>("client_secret", this.configuration.ClientSecret),
                    new KeyValuePair<string, string>("grant_type", "authorization_code"),
                    new KeyValuePair<string, string>("redirect_uri", this.configuration.RedirectUri),
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("code_verifier", codeVerifier),
                };

                try {
                
                    var response = await client.PostAsync(this.configuration.TokenEndpoint, new FormUrlEncodedContent(data));
                    if (!response.IsSuccessStatusCode)
                    {
                        throw this.CreateAuthorizationServerError(response);
                    }

                    return await response.Content.ReadFromJsonAsync<TokenResponse>();
                
                }
                catch (HttpRequestException exception)
                {
                    throw new AuthorizationServerException("Connectivity problem during an Authorization Code Grant", exception);
                }
            }
        }

        private AuthorizationClientException CreateAuthorizationServerError(HttpResponseMessage response)
        {
            return new AuthorizationClientException(response);
        }
    }
}
