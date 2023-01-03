namespace IO.Curity.OAuthAgent.Exceptions
{
    using IO.Curity.OAuthAgent.Entities;

    public class AuthorizationClientException : OAuthAgentException
    {
        public static AuthorizationClientException Create(GrantType grant, int statusCode, string responseText)
        {
            int clientStatusCode = 400;
            var errorCode = "authorization_error";

             if (grant == GrantType.UserInfo && statusCode == 401)
             {
                errorCode = "token_expired";
                clientStatusCode = 401;
            }

            if (grant == GrantType.RefreshToken && responseText.Contains("invalid_grant"))
            {
                errorCode = "session_expired";
                clientStatusCode = 401;
            }

            var logMessage = $"{grant} request failed with response: {responseText}";
            return new AuthorizationClientException(clientStatusCode, errorCode, logMessage);
        }

        private AuthorizationClientException(int statusCode, string code, string responseText) : base(
            "A request sent to the Authorization Server was rejected",
            400,
            "authorization_error",
            responseText)
        {
        }
    }
}
