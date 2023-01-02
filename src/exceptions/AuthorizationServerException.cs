namespace IO.Curity.OAuthAgent.Exceptions
{
    using System;

    public class AuthorizationServerException : OAuthAgentException
    {
        public AuthorizationServerException(string logMessage, Exception cause) : base(
            "A problem occurred with a request to the Authorization Server",
            502,
            "authorization_server_error",
            logMessage,
            cause)
        {
        }
    }
}
