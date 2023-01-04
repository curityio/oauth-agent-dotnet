namespace IO.Curity.OAuthAgent.Exceptions
{
    using System.Collections.Generic;
    using Microsoft.AspNetCore.Http;
    using Microsoft.Extensions.Logging;

    public class ErrorLogger
    {
        private readonly ILogger logger;

        public ErrorLogger(ILoggerFactory factory)
        {
            this.logger = factory.CreateLogger<ErrorLogger>();
        }

        public void Write(OAuthAgentException exception, HttpRequest request)
        {
            var fields = new List<string>();
            fields.Add(request.Method);
            fields.Add(request.Path);
            fields.AddRange(exception.GetLogFields());

            if (exception.StatusCode >= 500)
            {
                if (this.logger.IsEnabled(LogLevel.Error))
                {
                    this.logger.LogError(new EventId(), null, string.Join(", ", fields));
                }
            }
            else
            {
                if (this.logger.IsEnabled(LogLevel.Information))
                {
                    this.logger.LogInformation(new EventId(), null, string.Join(", ", fields));
                }
            }
        }
    }
}
