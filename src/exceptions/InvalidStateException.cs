namespace IO.Curity.OAuthAgent.Exceptions
{
    public class InvalidStateException : OAuthAgentException
    {
        public InvalidStateException() : base(
            "State parameter mismatch when completing a login",
            400,
            "invalid_request",
            null)
        {
        }
    }
}
