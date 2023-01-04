namespace IO.Curity.OAuthAgent.Exceptions
{
    public class ClientErrorResponse
    {
        public string Code { get; private set; }
        public string Message { get; private set; }

        public ClientErrorResponse(string code, string message)
        {
            this.Code = code;
            this.Message = message;
        }
    }
}
