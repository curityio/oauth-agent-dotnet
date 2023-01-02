namespace IO.Curity.OAuthAgent.Utilities
{
    using System.Linq;
    using Microsoft.AspNetCore.Http;
    using IO.Curity.OAuthAgent.Exceptions;

    public class RequestValidator
    {
        private readonly OAuthAgentConfiguration configuration;

        public RequestValidator(OAuthAgentConfiguration configuration)
        {
            this.configuration = configuration;
        }

        public void ValidateRequest(HttpRequest request, RequestValidationOptions options)
        {
            if (options.RequireTrustedOrigin)
            {
                var origin = request.Headers.Origin.FirstOrDefault() ?? "";
                if (!this.IsValidOrigin(origin))
                {
                    throw new UnauthorizedException($"The call is from an untrusted web origin: {origin}");
                }
            }
        }

        private bool IsValidOrigin(string origin)
        {
            if (!string.IsNullOrWhiteSpace(origin))
            {
                var trustedOrigins = this.configuration.TrustedWebOrigins.ToList();
                if (trustedOrigins.Exists(o => o.ToLower() == origin.ToLower()))
                {
                    return true;
                }
            }

            return false;
        }
    }
}
