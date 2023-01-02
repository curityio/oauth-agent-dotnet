namespace IO.Curity.OAuthAgent.Utilities
{
    using Microsoft.AspNetCore.Http;

    public class RequestValidator
    {
        public void ValidateRequest(HttpRequest request, RequestValidationOptions options)
        {
            System.Console.WriteLine("*** VALIDATING REQUEST");
        }
    }
}
