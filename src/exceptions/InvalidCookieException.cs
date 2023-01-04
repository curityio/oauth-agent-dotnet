namespace IO.Curity.OAuthAgent.Exceptions
{
    public class InvalidCookieException : OAuthAgentException
    {
        public InvalidCookieException(string logMessage) : base(
            "Access denied due to invalid request details",
            401,
            "unauthorized_request",
            logMessage)
        {
        }
    }
}
