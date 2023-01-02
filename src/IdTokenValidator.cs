namespace IO.Curity.OAuthAgent
{
    public class IdTokenValidator
    {
        private readonly OAuthAgentConfiguration configuration;

        public IdTokenValidator(OAuthAgentConfiguration configuration)
        {
            this.configuration = configuration;
        }

        public void Validate(string idToken)
        {
        }
    }
}
