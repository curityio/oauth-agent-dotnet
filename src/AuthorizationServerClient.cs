namespace IO.Curity.OAuthAgent
{
    using System;
    using System.Collections.Generic;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Net.Http.Json;
    using System.Text;
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

        /*
         * Send the authorization code and receive tokens
         */
        public async Task<TokenResponse> RedeemCodeForTokens(string code, string codeVerifier)
        {
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("accept", "application/json");

                var credential = $"{this.configuration.ClientID}:{this.configuration.ClientSecret}";
                var basicCredential = Convert.ToBase64String(Encoding.UTF8.GetBytes(credential));
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", basicCredential);

                var data = new[]
                {
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

        /*
         * Send the refresh token and receive a new set of tokens
         */
        public async Task<TokenResponse> RefreshAccessToken(string refreshToken)
        {
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("accept", "application/json");

                var credential = $"{this.configuration.ClientID}:{this.configuration.ClientSecret}";
                var basicCredential = Convert.ToBase64String(Encoding.UTF8.GetBytes(credential));
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", basicCredential);

                var data = new[]
                {
                    new KeyValuePair<string, string>("grant_type", "refresh_token"),
                    new KeyValuePair<string, string>("refresh_token", refreshToken),
                };

                try {
                
                    var response = await client.PostAsync(this.configuration.TokenEndpoint, new FormUrlEncodedContent(data));
                    if (!response.IsSuccessStatusCode)
                    {
                        throw await this.CreateAuthorizationServerError(response, GrantType.RefreshToken);
                    }

                    return await response.Content.ReadFromJsonAsync<TokenResponse>();
                }
                catch (HttpRequestException exception)
                {
                    throw new AuthorizationServerException("Connectivity problem during a Refresh Token Grant", exception);
                }
            }
        }

        /*
         * Send an access token and receive user info
         */
        public async Task<IDictionary<string, object>> GetUserInfo(string accessToken)
        {
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("accept", "application/json");
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                try
                {
                    var request = new HttpRequestMessage(HttpMethod.Post, this.configuration.UserInfoEndpoint);
                    var response = await client.SendAsync(request);
                    if (!response.IsSuccessStatusCode)
                    {
                        throw await this.CreateAuthorizationServerError(response, GrantType.UserInfo);
                    }

                    return await response.Content.ReadFromJsonAsync<Dictionary<string, object>>();
                }
                catch (HttpRequestException exception)
                {
                    throw new AuthorizationServerException("Connectivity problem during a User Info request", exception);
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
