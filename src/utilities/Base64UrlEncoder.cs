namespace IO.Curity.OAuthAgent.Utilities
{
    using System;
    
    public class Base64UrlEncoder
    {
        public static string Encode(byte[] bytes)
        {
            return Convert.ToBase64String(bytes)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }

        public static byte[] Decode(string stringToDecode) {
            
            string stringB64 = stringToDecode.Replace('-', '+').Replace('_', '/');
            int paddings = stringToDecode.Length % 4;
            if (paddings > 0)
            {
                stringB64 += new string('=', 4 - paddings);
            }

            return System.Convert.FromBase64String(stringB64);
        }
    }
}
