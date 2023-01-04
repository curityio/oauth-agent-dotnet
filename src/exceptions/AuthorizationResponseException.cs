namespace IO.Curity.OAuthAgent.Exceptions
{
    public class AuthorizationResponseException : OAuthAgentException
    {
        public AuthorizationResponseException(string error, string errorDescription) : base(
            errorDescription,
            400,
            error,
            null)
        {
            // Treat the prompt=none response as expiry related
            if (error == "login_required")
            {
                this.StatusCode = 401;
            }
        }
    }
}
