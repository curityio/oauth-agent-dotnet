namespace IO.Curity.OAuthAgent.Exceptions
{
    using System;
    using System.Collections.Generic;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Http;
    using Microsoft.Extensions.Logging;

    public sealed class UnhandledExceptionMiddleware
    {
        private readonly RequestDelegate next;

        public UnhandledExceptionMiddleware(RequestDelegate next)
        {
            this.next = next;
        }

        public async Task Invoke(HttpContext context, ILoggerFactory loggerFactory)
        {
            try
            {
                await this.next(context);
            }
            catch (Exception exception)
            {
                var oauthAgentException = this.GetOAuthAgentException(exception);
                
                this.LogError(oauthAgentException, context.Request, loggerFactory.CreateLogger<UnhandledExceptionMiddleware>());

                var response = context.Response;
                response.StatusCode = oauthAgentException.StatusCode;
                var errorResponse = oauthAgentException.GetErrorResponse();
                await response.WriteAsJsonAsync(errorResponse);

            }   
        }

        private OAuthAgentException GetOAuthAgentException(Exception ex)
        {
            if (ex is OAuthAgentException)
            {
                return ex as OAuthAgentException;
            }
            
            return new UnhandledException(ex);
        }

        private void LogError(OAuthAgentException exception, HttpRequest request, ILogger logger)
        {
            var fields = new List<string>();
            fields.Add(request.Method);
            fields.Add(request.Path);
            fields.AddRange(exception.GetLogFields());

            if (exception.StatusCode >= 500)
            {
                if (logger.IsEnabled(LogLevel.Error))
                {
                    logger.LogError(new EventId(), null, string.Join(", ", fields));
                }
            }
            else
            {
                if (logger.IsEnabled(LogLevel.Information))
                {
                    logger.LogInformation(new EventId(), null, string.Join(", ", fields));
                }
            }
        }
    }
}
