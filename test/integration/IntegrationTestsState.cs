namespace IO.Curity.OAuthAgent.Test
{
    using System;
    using Xunit;

    [CollectionDefinition("default")]
    public class IntegrationTestsState : IDisposable
    {
        public IntegrationTestsState()
        {
        }

        public void Dispose()
        {
        }
    }
}
