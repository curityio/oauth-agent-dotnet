namespace IO.Curity.OAuthAgent.Exceptions
{
    using System.Net.Http;

    public class AuthorizationClientException : OAuthAgentException
    {
        public AuthorizationClientException(HttpResponseMessage response) : base(
            "A request sent to the Authorization Server was rejected",
            400,
            "authorization_error",
            null)
        {
        }
    }
}
