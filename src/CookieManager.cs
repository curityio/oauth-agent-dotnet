namespace IO.Curity.OAuthAgent
{
    using System;
    using System.Collections.Generic;
    using System.Text.Json;
    using Microsoft.AspNetCore.Http;
    using Microsoft.Extensions.Logging;
    using IO.Curity.OAuthAgent.Entities;
    using IO.Curity.OAuthAgent.Utilities;

    /*
     * Encapsulates the main cookie logic, called from controllers
     */ 
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

        private readonly ILogger logger;

        public CookieManager(OAuthAgentConfiguration configuration, ILoggerFactory factory)
        {
            this.configuration = configuration;
            this.logger = factory.CreateLogger<CookieManager>();
        }

        /*
         * Create a temp cookie to store values when issuing the authorization request
         */
        public (string, string, CookieOptions) CreateTempLoginStateCookie(string state, string codeVerifier)
        {
            var data = new TempLoginData{ State = state, CodeVerifier = codeVerifier };
            string serialized = JsonSerializer.Serialize(data);
            string encrypted = CookieEncrypter.EncryptCookie(this.configuration.CookieEncryptionKey, serialized);
            
            return (this.GetCookieName(CookieName.login), encrypted, this.GetCookieOptions("/"));
        }

        /*
         * Read back the login state when receiving the authorization response
         */
        public TempLoginData GetLoginStateCookieSafe(HttpRequest request)
        {
            var encrypted = GetEncryptedCookieSafe(request, CookieName.login);
            if (string.IsNullOrWhiteSpace(encrypted))
            {
                return null;
            }

            var decrypted = DecryptCookieSafe(CookieName.login, encrypted);
            if (string.IsNullOrWhiteSpace(decrypted))
            {
                return null;
            }

            return JsonSerializer.Deserialize<TempLoginData>(decrypted);
        }

        /*
         * Get a cookie and allow the caller to deal with throwing exceptions
         */
        public string GetCookieSafe(HttpRequest request, CookieName name)
        {
            var encrypted = GetEncryptedCookieSafe(request, name);
            if (string.IsNullOrWhiteSpace(encrypted))
            {
                return "";
            }

            return DecryptCookieSafe(name, encrypted) ?? "";
        }

        /*
         * After completing a login, return the data needed to write tokens into cookies
         */
        public List<(string, string, CookieOptions)> CreateCookies(TokenResponse tokenResponse, string csrfToken)
        {
            var results = new List<(string, string, CookieOptions)>();

            results.AddRange(this.WriteTokensToCookies(tokenResponse));
            
            var csrfCookie = CookieEncrypter.EncryptCookie(this.configuration.CookieEncryptionKey, csrfToken);
            results.Add((this.GetCookieName(CookieName.csrf), csrfCookie, this.GetCookieOptions("/")));

            var tempLoginCookie = "";
            results.Add((this.GetCookieName(CookieName.login), tempLoginCookie, this.GetDeleteCookieOptions("/")));

            return results;
        }

        /*
         * After refreshing tokens, return the data needed to update cookies containing tokens
         */
        public List<(string, string, CookieOptions)> RefreshCookies(TokenResponse tokenResponse)
        {
            return this.WriteTokensToCookies(tokenResponse);
        }

        /*
         * After logging out, return the data needed to expire all cookies
         */
        public List<(string, string, CookieOptions)> ExpireAllCookies()
        {
            var results = new List<(string, string, CookieOptions)>();

            results.Add((this.GetCookieName(CookieName.access), "", this.GetDeleteCookieOptions("/")));
            results.Add((this.GetCookieName(CookieName.refresh), "", this.GetDeleteCookieOptions("/oauth-agent/refresh")));
            results.Add((this.GetCookieName(CookieName.id), "", this.GetDeleteCookieOptions("/oauth-agent/claims")));
            results.Add((this.GetCookieName(CookieName.csrf), "", this.GetDeleteCookieOptions("/")));

            return results;
        }

        /*
         * Form the cookie full name from the configured prefix
         */
        private string GetCookieName(CookieName name)
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

        /*
         * Get a cookie by name from the HTTP request
         */
        private string GetEncryptedCookieSafe(HttpRequest request, CookieName name)
        {
            if (request.Cookies != null)
            {
                var cookieName = this.GetCookieName(name);
                var cookie = request.Cookies[cookieName];
                if (!string.IsNullOrWhiteSpace(cookie))
                {
                    return cookie;
                }
            }

            return "";
        }

        /*
         * Handle cookie decryption defensively, in case the browser has leftover cookies with an old encryption key
         */
        private string DecryptCookieSafe(CookieName name, string encryptedCookieValue)
        {
            if (!string.IsNullOrWhiteSpace(encryptedCookieValue))
            {
                try
                {
                    return CookieEncrypter.DecryptCookie(this.configuration.CookieEncryptionKey, encryptedCookieValue);
                }
                catch (Exception exception)
                {
                    logger.LogInformation(new EventId(), exception, $"Unable to decrypt {name} cookie");
                }
            }
            
            return "";
        }

        /*
         * After validating the ID token, write tokens to cookies
         */
        private List<(string, string, CookieOptions)> WriteTokensToCookies(TokenResponse tokenResponse)
        {
            var results = new List<(string, string, CookieOptions)>();

            var accessCookie = CookieEncrypter.EncryptCookie(this.configuration.CookieEncryptionKey, tokenResponse.AccessToken);
            results.Add((this.GetCookieName(CookieName.access), accessCookie, this.GetCookieOptions("/")));

            if (!string.IsNullOrWhiteSpace(tokenResponse.RefreshToken))
            {
                var refreshCookie = CookieEncrypter.EncryptCookie(this.configuration.CookieEncryptionKey, tokenResponse.RefreshToken);
                results.Add((this.GetCookieName(CookieName.refresh), refreshCookie, this.GetCookieOptions("/oauth-agent/refresh")));
            }
            
            if (!string.IsNullOrWhiteSpace(tokenResponse.IdToken))
            {
                var idCookie = CookieEncrypter.EncryptCookie(this.configuration.CookieEncryptionKey, tokenResponse.IdToken);
                results.Add((this.GetCookieName(CookieName.id), idCookie, this.GetCookieOptions("/oauth-agent/claims")));
            }

            return results;
        }

        /*
         * Get options when creating a cookie
         */
        private CookieOptions GetCookieOptions(string cookiePath)
        {
            var fullCookiePath = string.IsNullOrWhiteSpace(this.configuration.CookieBasePath)
                ? cookiePath : this.configuration.CookieBasePath + cookiePath;

            bool useSsl = !string.IsNullOrWhiteSpace(this.configuration.ServerCertPath);
            return new CookieOptions {
                Domain = this.configuration.CookieDomain,
                Path = fullCookiePath, 
                Secure = useSsl,
                HttpOnly = true,
                SameSite = SameSiteMode.Strict,
            };
        }

        /*
         * Get options when expiring a cookie
         */
        private CookieOptions GetDeleteCookieOptions(string cookiePath)
        {
            var options = this.GetCookieOptions(cookiePath);
            options.Expires = DateTimeOffset.UtcNow - TimeSpan.FromDays(1);
            return options;
        }
    }
}
