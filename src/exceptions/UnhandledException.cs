namespace IO.Curity.OAuthAgent.Exceptions
{
    using System;

    public class UnhandledException : OAuthAgentException
    {
        public UnhandledException(Exception exception) : base(
            "A technical problem occurred in the OAuth Agent",
            500,
            "server_error",
            "Unhandled exception",
            exception)
        {
        }
    }
}
