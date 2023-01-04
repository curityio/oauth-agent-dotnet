namespace IO.Curity.OAuthAgent.Entities
{
    public class EndAuthorizationResponse
    {
        public bool Handled { get; set; }

        public bool IsLoggedIn  { get; set; }

        public string Csrf { get; set; }
    }
}
