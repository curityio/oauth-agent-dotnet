namespace IO.Curity.OAuthAgent
{
    using System;

    public class OAuthAgentConfiguration
    {
        public int Port { get; set; }
        public string ServerCertPath { get; set; }
        public string ServerCertPassword { get; set; }

        public string ClientID { get; set; }
        public string ClientSecret { get; set; }
        public string RedirectUri { get; set; }
        public string PostLogoutRedirectUri { get; set; }
        public string Scope { get; set; }

        public string[] TrustedWebOrigins { get; set; }
        public bool CorsEnabled { get; set; }
        public string CookieNamePrefix  { get; set; }
        public string CookieDomain { get; set; }
        public string CookieEncryptionKey  { get; set; }

        public string AuthorizeEndpoint { get; set; }
        public string LogoutEndpoint { get; set; }
        public string TokenEndpoint { get; set; }
        public string UserInfoEndpoint { get; set; }

        public void FromEnvironment()
        {
            Port = int.Parse(Get("PORT"));
            ServerCertPath = Get("SERVER_CERT_P12_PATH", false);
            ServerCertPassword = Get("SERVER_CERT_P12_PASSWORD", false);

            ClientID = Get("CLIENT_ID");
            ClientSecret = Get("CLIENT_SECRET");
            RedirectUri = Get("REDIRECT_URI");
            PostLogoutRedirectUri = Get("POST_LOGOUT_REDIRECT_URI");
            Scope = Get("SCOPE");

            TrustedWebOrigins = new String[] { Get("TRUSTED_WEB_ORIGIN") };
            CorsEnabled = bool.Parse(Get("CORS_ENABLED"));
            CookieNamePrefix = Get("COOKIE_NAME_PREFIX");
            CookieDomain = Get("COOKIE_DOMAIN");
            CookieEncryptionKey = Get("COOKIE_ENCRYPTION_KEY");
            
            AuthorizeEndpoint = Get("AUTHORIZE_ENDPOINT");
            LogoutEndpoint = Get("LOGOUT_ENDPOINT");
            TokenEndpoint = Get("TOKEN_ENDPOINT");
            UserInfoEndpoint = Get("USERINFO_ENDPOINT");
        }

        private String Get(string key, bool mandatory=true)
        {
            string value = Environment.GetEnvironmentVariable(key);
            if (mandatory && string.IsNullOrWhiteSpace(value))
            {
                throw new ArgumentException($"The environment variable {key} is not set");
            }

            return value;
        }
    }
}
