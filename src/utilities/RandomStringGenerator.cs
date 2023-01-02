namespace IO.Curity.OAuthAgent.Utilities
{
    using System.Security.Cryptography;
    using System.Text;
    
    public class RandomStringGenerator
    {
        public static string CreateState()
        {
            var bytes = new byte[32];
            RandomNumberGenerator.Create().GetBytes(bytes);
            return Base64UrlEncoder.Encode(bytes);
        }

        public static (string, string) CreateCodeVerifier()
        {
            var bytes = new byte[32];
            RandomNumberGenerator.Create().GetBytes(bytes);
            var codeVerifier = Base64UrlEncoder.Encode(bytes);

            using (var sha256 = SHA256.Create())
            {
                var codeChallengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
                var codeChallenge = Base64UrlEncoder.Encode(codeChallengeBytes);
                return (codeVerifier, codeChallenge);
            }
        }
    }
}
