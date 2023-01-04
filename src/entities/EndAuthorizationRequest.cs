namespace IO.Curity.OAuthAgent.Entities
{
    public class EndAuthorizationRequest
    {
        public string PageUrl{ get; private set; }

        public EndAuthorizationRequest(string pageUrl)
        {
            this.PageUrl = pageUrl;
        }
    }
}
