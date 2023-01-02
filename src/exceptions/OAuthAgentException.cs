namespace IO.Curity.OAuthAgent.Exceptions
{
    using System;
    using System.Collections.Generic;

    public class OAuthAgentException : Exception
    {
        public int StatusCode {get; private set; }

        private readonly string code;
        private readonly string logMessage;

        public OAuthAgentException(
            string message,
            int statusCode,
            string code,
            string logMessage,
            Exception cause = null) : base(message, cause)
        {
            this.StatusCode = statusCode;
            this.code = code;
            this.logMessage = logMessage;
        }

        public ErrorResponse GetErrorResponse()
        {
            return new ErrorResponse(this.code, this.Message);
        }

        public List<string> GetLogFields()
        {
            var data = new List<string>();
            data.Add(this.StatusCode.ToString());
            data.Add(this.code);
            data.Add(this.Message);
            
            if (!string.IsNullOrWhiteSpace(this.logMessage)) {
                data.Add(this.logMessage);
            }

            if (this.StatusCode >= 500) {
                data.Add(this.StackTrace);
            }

            return data;
        }
    }
}
