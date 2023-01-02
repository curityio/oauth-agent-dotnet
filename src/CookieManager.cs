namespace IO.Curity.OAuthAgent
{
    using System;
    using System.Collections.Generic;
    using System.Text.Json;
    using Microsoft.AspNetCore.Http;
    using IO.Curity.OAuthAgent.Entities;
    using IO.Curity.OAuthAgent.Utilities;

    public class CookieManager
    {
        public enum CookieName
        {
            login,
            refresh,
            access,
            id,
            csrf,
        }

        private readonly OAuthAgentConfiguration configuration;

        public CookieManager(OAuthAgentConfiguration configuration)
        {
            this.configuration = configuration;
        }

        /*
         * When a login request is created, write a temp cookie with the state and code verifier
         */
        public (string, string, CookieOptions) CreateTempLoginStateCookie(string state, string codeVerifier)
        {
            var data = new TempLoginData{ State = state, CodeVerifier = codeVerifier };
            string serialized = JsonSerializer.Serialize(data);
            string encrypted = CookieEncrypter.EncryptCookie(this.configuration.CookieEncryptionKey, serialized);
            
            string cookieName = $"{this.configuration.CookieNamePrefix}-login";
            return (cookieName, encrypted, this.GetCookieOptions("/"));
        }

        /*
         * If a login response is handled, read the stored values, which will be validated
         */
        public TempLoginData ReadStoredLoginStateCookie(string encryptedCookieValue)
        {
            if (string.IsNullOrWhiteSpace(encryptedCookieValue))
            {
                return null;
            }
            
            string decrypted = CookieEncrypter.DecryptCookie(this.configuration.CookieEncryptionKey, encryptedCookieValue);
            return JsonSerializer.Deserialize<TempLoginData>(decrypted);
        }

        public List<(string, string, CookieOptions)> CreateCookies(TokenResponse tokenResponse)
        {
            var results = new List<(string, string, CookieOptions)>();

            string accessCookieName = $"{this.configuration.CookieNamePrefix}-at";
            var accessToken = CookieEncrypter.EncryptCookie(this.configuration.CookieEncryptionKey,tokenResponse.AccessToken);
            results.Add((accessCookieName, accessToken, this.GetCookieOptions("/")));

            string refreshCookieName = $"{this.configuration.CookieNamePrefix}-auth";
            var refreshToken = CookieEncrypter.EncryptCookie(this.configuration.CookieEncryptionKey,tokenResponse.RefreshToken);
            results.Add((refreshCookieName, refreshToken, this.GetCookieOptions("/refresh")));

            string idCookieName = $"{this.configuration.CookieNamePrefix}-id";
            var idToken = CookieEncrypter.EncryptCookie(this.configuration.CookieEncryptionKey,tokenResponse.RefreshToken);
            results.Add((idCookieName, idToken, this.GetCookieOptions("/claims")));

            return results;
        }

        public string GetCookieName(CookieName name)
        {
            switch (name)
            {
                case CookieName.login:
                    return $"{this.configuration.CookieNamePrefix}-login";

                case CookieName.refresh:
                    return $"{this.configuration.CookieNamePrefix}-auth";

                case CookieName.access:
                    return $"{this.configuration.CookieNamePrefix}-at";

                case CookieName.id:
                    return $"{this.configuration.CookieNamePrefix}-id";

                case CookieName.csrf:
                    return $"{this.configuration.CookieNamePrefix}-csrf";
            }

            throw new ArgumentException("Invalid  cookie name requested");
        }

        private CookieOptions GetCookieOptions(string cookiePath)
        {
            bool useSsl = !string.IsNullOrWhiteSpace(this.configuration.ServerCertPath);
            return new CookieOptions {
                Domain = this.configuration.CookieDomain,
                Path = cookiePath, 
                Secure = useSsl,
                HttpOnly = true,
                SameSite = SameSiteMode.Strict,
            };
        }
    }
}
