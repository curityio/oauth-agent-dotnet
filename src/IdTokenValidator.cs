namespace IO.Curity.OAuthAgent
{
    using System.IdentityModel.Tokens.Jwt;
    using System.Linq;
    using IO.Curity.OAuthAgent.Exceptions;

    /*
     * Before issuing cookies, make sanity checks to ensure that the issuer and audience are configured correctly
     * The ID token is received over a trusted back channel connection so signature checks are not needed
     * https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
     */
    public class IdTokenValidator
    {
        private readonly OAuthAgentConfiguration configuration;

        public IdTokenValidator(OAuthAgentConfiguration configuration)
        {
            this.configuration = configuration;
        }

        public void Validate(string idToken)
        {
            var token = new JwtSecurityToken(idToken);
            
            if (token.Issuer != this.configuration.Issuer)
            {
                throw new InvalidIdTokenException("Unexpected iss claim received in ID token");
            }

            if (!token.Audiences.Any(a => a == this.configuration.ClientID))
            {
                throw new InvalidIdTokenException("Unexpected aud claim received in ID token");
            }
        }
    }
}
