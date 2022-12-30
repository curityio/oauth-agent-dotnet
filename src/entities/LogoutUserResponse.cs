namespace IO.Curity.OAuthAgent.Entities
{
    public class LogoutUserResponse
    {
        public string Url {get; set; }

        public LogoutUserResponse(string url)
        {
            Url = url;
        }
    }
}
