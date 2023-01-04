namespace IO.Curity.OAuthAgent.Exceptions
{
    public class InvalidIdTokenException : OAuthAgentException
    {
        public InvalidIdTokenException(string logMessage) : base(
            "ID Token missing or invalid",
            400,
            "invalid_request",
            logMessage)
        {
        }
    }
}
