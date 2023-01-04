namespace IO.Curity.OAuthAgent.Exceptions
{
    using System;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Http;

    public class UnhandledExceptionMiddleware
    {
        private readonly RequestDelegate next;

        public UnhandledExceptionMiddleware(RequestDelegate next)
        {
            this.next = next;
        }

        public async Task Invoke(HttpContext context, ErrorLogger logger)
        {
            try
            {
                await this.next(context);
            }
            catch (Exception exception)
            {
                // Process and log the exception details
                var oauthAgentException = this.GetOAuthAgentException(exception);
                logger.Write(oauthAgentException, context.Request);

                // Write the client error response
                var response = context.Response;
                response.StatusCode = oauthAgentException.StatusCode;
                var errorResponse = oauthAgentException.GetErrorResponse();
                await response.WriteAsJsonAsync(errorResponse);

            }   
        }

        private OAuthAgentException GetOAuthAgentException(Exception exception)
        {
            if (exception is OAuthAgentException)
            {
                return exception as OAuthAgentException;
            }
            
            
            return new UnhandledException(exception);
        }
    }
}
