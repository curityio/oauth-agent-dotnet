namespace IO.Curity.OAuthAgent.Entities
{
    using System.Collections.Generic;

    public class StartAuthorizationParameters
    {
        public List<ExtraParams> ExtraParams { get; private set; }

        public StartAuthorizationParameters(List<ExtraParams> extraParams)
        {
            this.ExtraParams = extraParams;
        }
    }
}
