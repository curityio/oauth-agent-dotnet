namespace IO.Curity.OAuthAgent.Entities
{
    using System.Text.Json.Serialization;

    public class TokenResponse
    {
        [JsonPropertyName("access_token")]
        public string AccessToken { get; private set; }

        [JsonPropertyName("refresh_token")]
        public string RefreshToken { get; private set; }

        [JsonPropertyName("id_token")]
        public string IdToken { get; private set; }
        
        public TokenResponse(string accessToken, string refreshToken, string idToken)
        {
            this.AccessToken = accessToken;
            this.RefreshToken = refreshToken;
            this.IdToken = idToken;
        }
    }
}
