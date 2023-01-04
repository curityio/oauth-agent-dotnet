namespace IO.Curity.OAuthAgent.Exceptions
{
    public class InvalidRequestException : OAuthAgentException
    {
        public InvalidRequestException(string message) : base(
            message,
            400,
            "invalid_request",
            null)
        {
        }
    }
}
