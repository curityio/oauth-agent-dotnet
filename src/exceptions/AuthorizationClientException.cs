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
                clientStatusCode = 401;
                errorCode = "token_expired";
            }

            if (grant == GrantType.RefreshToken && responseText.Contains("invalid_grant"))
            {
                clientStatusCode = 401;
                errorCode = "session_expired";
            }

            var logMessage = $"{grant} request failed with response: {responseText}";
            return new AuthorizationClientException(clientStatusCode, errorCode, logMessage);
        }

        private AuthorizationClientException(int statusCode, string code, string responseText) : base(
            "A request sent to the Authorization Server was rejected",
            statusCode,
            code,
            responseText)
        {
        }
    }
}
