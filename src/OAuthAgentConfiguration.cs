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

        public string Issuer { get; set; }
        public string AuthorizeEndpoint { get; set; }
        public string LogoutEndpoint { get; set; }
        public string TokenEndpoint { get; set; }
        public string UserInfoEndpoint { get; set; }

        /*
         * Docker deployments provide configuration values via environment variables
         */
        public void FromEnvironment()
        {
            this.Port = int.Parse(Get("PORT"));
            this.ServerCertPath = Get("SERVER_CERT_P12_PATH", false);
            this.ServerCertPassword = Get("SERVER_CERT_P12_PASSWORD", false);

            this.ClientID = Get("CLIENT_ID");
            this.ClientSecret = Get("CLIENT_SECRET");
            this.RedirectUri = Get("REDIRECT_URI");
            this.PostLogoutRedirectUri = Get("POST_LOGOUT_REDIRECT_URI");
            this.Scope = Get("SCOPE");

            this.TrustedWebOrigins = new String[] { Get("TRUSTED_WEB_ORIGIN") };
            this.CorsEnabled = bool.Parse(Get("CORS_ENABLED"));
            this.CookieNamePrefix = Get("COOKIE_NAME_PREFIX");
            this.CookieDomain = Get("COOKIE_DOMAIN");
            this.CookieEncryptionKey = Get("COOKIE_ENCRYPTION_KEY");
            
            this.Issuer = Get("ISSUER");
            this.AuthorizeEndpoint = Get("AUTHORIZE_ENDPOINT");
            this.LogoutEndpoint = Get("LOGOUT_ENDPOINT");
            this.TokenEndpoint = Get("TOKEN_ENDPOINT");
            this.UserInfoEndpoint = Get("USERINFO_ENDPOINT");
        }

        private String Get(string key, bool mandatory = true)
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
