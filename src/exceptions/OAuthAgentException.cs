namespace IO.Curity.OAuthAgent.Exceptions
{
    using System;
    using System.Collections.Generic;

    public class OAuthAgentException : Exception
    {
        public int StatusCode { get; set; }

        private readonly string code;
        private readonly string logMessage;
        private readonly string originalStackTrace;

        public OAuthAgentException(
            string message,
            int statusCode,
            string code,
            string logMessage,
            Exception cause = null) : base(message, cause)
        {
            this.StatusCode = statusCode;
            this.code = code;

            if (cause != null && !string.IsNullOrWhiteSpace(cause.Message))
            {
                this.logMessage = $"{logMessage} : {cause.Message}";
            }
            else
            {
                this.logMessage = logMessage;
            }

            this.originalStackTrace = cause?.StackTrace ?? this.StackTrace;
        }

        public ClientErrorResponse GetErrorResponse()
        {
            return new ClientErrorResponse(this.code, this.Message);
        }

        public List<string> GetLogFields()
        {
            var data = new List<string>();
            data.Add(this.StatusCode.ToString());
            data.Add(this.code);
            data.Add(this.Message);
            
            if (!string.IsNullOrWhiteSpace(this.logMessage))
            {
                data.Add(this.logMessage);
            }

            if (this.StatusCode >= 500)
            {
                if (!string.IsNullOrWhiteSpace(this.originalStackTrace))
                {
                    data.Add(this.originalStackTrace);
                }
            }

            return data;
        }
    }
}
