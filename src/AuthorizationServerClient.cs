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
                        throw await this.CreateAuthorizationServerError(response, GrantType.AuthorizationCode);
                    }

                    return await response.Content.ReadFromJsonAsync<TokenResponse>();
                
                }
                catch (HttpRequestException exception)
                {
                    throw new AuthorizationServerException("Connectivity problem during an Authorization Code Grant", exception);
                }
            }
        }

        private async Task<OAuthAgentException> CreateAuthorizationServerError(HttpResponseMessage response, GrantType grantType)
        {
            var text = await response.Content.ReadAsStringAsync();

            if ((int)response.StatusCode >= 500)
            {
                return new AuthorizationServerException($"Server error response executing {grantType}: {text}", null);
            }

            return AuthorizationClientException.Create(grantType, (int)response.StatusCode, text);
        }
    }
}
