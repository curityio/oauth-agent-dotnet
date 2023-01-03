namespace IO.Curity.OAuthAgent
{
    using System;
    using System.Collections.Generic;
    using System.Text.Json;
    using Microsoft.AspNetCore.Http;
    using IO.Curity.OAuthAgent.Entities;
    using IO.Curity.OAuthAgent.Exceptions;
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
         * Create a temp cookie to store values between the authorization request and response
         */
        public (string, string, CookieOptions) CreateTempLoginStateCookie(string state, string codeVerifier)
        {
            var data = new TempLoginData{ State = state, CodeVerifier = codeVerifier };
            string serialized = JsonSerializer.Serialize(data);
            string encrypted = CookieEncrypter.EncryptCookie(this.configuration.CookieEncryptionKey, serialized);
            
            return (this.GetCookieName(CookieName.login), encrypted, this.GetCookieOptions("/"));
        }

        /*
         * After processing the response, write tokens into cookies, and 
         */
        public List<(string, string, CookieOptions)> CreateCookies(TokenResponse tokenResponse, string csrfToken)
        {
            var results = new List<(string, string, CookieOptions)>();

            var accessCookie = CookieEncrypter.EncryptCookie(this.configuration.CookieEncryptionKey, tokenResponse.AccessToken);
            results.Add((this.GetCookieName(CookieName.access), accessCookie, this.GetCookieOptions("/")));

            var refreshCookie = CookieEncrypter.EncryptCookie(this.configuration.CookieEncryptionKey, tokenResponse.RefreshToken);
            results.Add((this.GetCookieName(CookieName.refresh), refreshCookie, this.GetCookieOptions("/refresh")));
            
            var idCookie = CookieEncrypter.EncryptCookie(this.configuration.CookieEncryptionKey, tokenResponse.RefreshToken);
            results.Add((this.GetCookieName(CookieName.id), idCookie, this.GetCookieOptions("/claims")));

            var csrfCookie = CookieEncrypter.EncryptCookie(this.configuration.CookieEncryptionKey, csrfToken);
            results.Add((this.GetCookieName(CookieName.csrf), csrfCookie, this.GetCookieOptions("/")));

            var tempLoginCookie = "";
            results.Add((this.GetCookieName(CookieName.login), tempLoginCookie, this.GetDeleteCookieOptions("/")));

            return results;
        }

        public TempLoginData DecryptLoginStateCookie(string encryptedCookieValue)
        {
            var decrypted = DecryptCookieSafe(encryptedCookieValue, true);
            if (string.IsNullOrWhiteSpace(decrypted))
            {
                return null;
            }

            return JsonSerializer.Deserialize<TempLoginData>(decrypted);
        }

        public string DecryptCsrfCookie(string encryptedCookieValue)
        {
            return DecryptCookieSafe(encryptedCookieValue, true) ?? "";
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

        private CookieOptions GetDeleteCookieOptions(string cookiePath)
        {
            var options = this.GetCookieOptions(cookiePath);
            options.Expires = DateTimeOffset.UtcNow - TimeSpan.FromDays(1);
            return options;
        }

        /*
         * Handle cookie decryption defensively, in case the browser has leftover cookies with an old encryption key
         */
        private string DecryptCookieSafe(string encryptedCookieValue, bool isExpected = false)
        {
            if (!string.IsNullOrWhiteSpace(encryptedCookieValue))
            {
                try
                {
                    return CookieEncrypter.DecryptCookie(this.configuration.CookieEncryptionKey, encryptedCookieValue);
                }
                catch (Exception exception)
                {
                    if (!isExpected)
                    {
                        throw new CookieDecryptionException(exception);
                    }
                }
            }

            return null;
        }
    }
}
