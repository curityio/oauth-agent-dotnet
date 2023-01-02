namespace IO.Curity.OAuthAgent.Middleware
{
    using System;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Http;

    public sealed class UnhandledExceptionMiddleware
    {
        private readonly RequestDelegate next;

        public UnhandledExceptionMiddleware(RequestDelegate next)
        {
            this.next = next;
        }

        public async Task Invoke(HttpContext context)
        {
            try
            {
                await this.next(context);
            }
            catch (Exception exception)
            {
                System.Console.WriteLine(exception);
                
                var response = context.Response;
                response.ContentType = "application/json";
                response.StatusCode = 500;
                await response.WriteAsync("OAuth Agent Problem Encountered");
            }   
        }
    }
}
