namespace IO.Curity.OAuthAgent
{
    public class AuthorizationRequestData
    {
        public string AuthorizationRequestUrl { get; private set; }

        public string CodeVerifier { get; private set; }

        public string State { get; private set; }

        public AuthorizationRequestData(
            string authorizationRequestUrl,
            string codeVerifier,
            string state)
        {
            this.AuthorizationRequestUrl = authorizationRequestUrl;
            this.CodeVerifier = codeVerifier;
            this.State = state;
        }
    }
}
