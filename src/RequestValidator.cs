namespace IO.Curity.OAuthAgent
{
    using System.Linq;
    using Microsoft.AspNetCore.Http;
    using IO.Curity.OAuthAgent.Exceptions;

    /*
     * Make basic web security checks in line with OWASP web security best practice
     */
    public class RequestValidator
    {
        private readonly OAuthAgentConfiguration configuration;

        public RequestValidator(OAuthAgentConfiguration configuration)
        {
            this.configuration = configuration;
        }

        public void ValidateRequest(HttpRequest request, bool requireTrustedOrigin = true, bool requireCsrfHeader = true, string csrfToken = "")
        {
            // The origin header is not sent on GET requests in same site deployments, but is verified otherwise
            if (requireTrustedOrigin)
            {
                var origin = request.Headers.Origin.FirstOrDefault() ?? "";
                if (!this.IsValidOrigin(origin))
                {
                    throw new UnauthorizedException($"The call is from an untrusted web origin: {origin}");
                }
            }

            // The CSRF header is validated in POST requests after login
            if (requireCsrfHeader)
            {
                var csrfHeader = request.Headers[$"x-{this.configuration.CookieNamePrefix}-csrf"];
                if (csrfHeader.Count == 0)
                {
                    throw new UnauthorizedException("No CSRF cookie was supplied in a POST request");
                }

                if (csrfHeader != csrfToken)
                {
                    throw new UnauthorizedException("The CSRF header did not match the CSRF cookie in a POST request");
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
