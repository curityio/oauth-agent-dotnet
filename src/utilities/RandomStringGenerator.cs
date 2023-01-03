namespace IO.Curity.OAuthAgent.Utilities
{
    using System.Security.Cryptography;
    using System.Text;
    
    public class RandomStringGenerator
    {
        public static string CreateState()
        {
            return CreateRandomString();
        }

        public static (string, string) CreateCodeVerifier()
        {
            var codeVerifier = CreateRandomString();
            using (var sha256 = SHA256.Create())
            {
                var codeChallengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
                var codeChallenge = Base64UrlEncoder.Encode(codeChallengeBytes);
                return (codeVerifier, codeChallenge);
            }
        }

        public static string CreateCsrfToken()
        {
            return CreateRandomString();
        }

        private static string CreateRandomString()
        {
            var bytes = new byte[32];
            RandomNumberGenerator.Create().GetBytes(bytes);
            return Base64UrlEncoder.Encode(bytes);
        }
    }
}
