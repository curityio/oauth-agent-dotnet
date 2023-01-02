namespace IO.Curity.OAuthAgent.Exceptions
{
    public class UnauthorizedException : OAuthAgentException
    {
        public UnauthorizedException(string logMessage) : base(
            "Access denied due to invalid request details",
            401,
            "unauthorized_request",
            logMessage)
        {
        }
    }
}
