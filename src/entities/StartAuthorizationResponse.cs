namespace IO.Curity.OAuthAgent.Entities
{
    public class StartAuthorizationResponse
    {
        public string AuthorizationRequestUrl {get; set; }

        public StartAuthorizationResponse(string authorizationRequestUrl)
        {
            AuthorizationRequestUrl = authorizationRequestUrl;
        }
    }
}
