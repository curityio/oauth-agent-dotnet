namespace IO.Curity.OAuthAgent.Exceptions
{
    using System;

    public class CookieDecryptionException : OAuthAgentException
    {
        public CookieDecryptionException(Exception exception) : base(
            "Access denied due to invalid request details",
            401,
            "unauthorized_request",
            "A received cookie failed decryption",
            exception)
        {
        }
    }
}
