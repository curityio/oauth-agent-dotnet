namespace IO.Curity.OAuthAgent.Utilities
{
    public class OAuthQueryParams
    {
        public string Code { get; private set; }

        public string State { get; private set; }

        public OAuthQueryParams(string code, string state)
        {
            this.Code = code;
            this.State = state;
        }
    }
}
