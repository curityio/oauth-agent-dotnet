namespace IO.Curity.OAuthAgent.Exceptions
{
    public class ErrorResponse
    {
        public string Code { get; private set; }
        public string Message { get; private set; }

        public ErrorResponse(string code, string message)
        {
            this.Code = code;
            this.Message = message;
        }
    }
}
