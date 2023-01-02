namespace IO.Curity.OAuthAgent.Utilities
{
    public class RequestValidationOptions
    {
        public bool RequireTrustedOrigin { get; set; }

        public bool RequireCsrfHeader { get; set; }
    }
}
