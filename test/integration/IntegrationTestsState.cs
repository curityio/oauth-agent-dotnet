namespace IO.Curity.OAuthAgent.Test
{
    using System;
    using System.IO;
    using Microsoft.Extensions.Configuration;
    using Xunit;

    [CollectionDefinition("default")]
    public class IntegrationTestsState : IDisposable
    {
        public OAuthAgentConfiguration Configuration { get; private set; }

        public IntegrationTestsState()
        {
            var configFilePath = Path.Combine(System.IO.Directory.GetCurrentDirectory(), "../../../../../appsettings-dev.json");
            
            var configurationRoot = new ConfigurationBuilder()
                .AddJsonFile(configFilePath)
                .Build();

            this.Configuration = new OAuthAgentConfiguration();
            configurationRoot.GetSection("OAuthAgentConfiguration").Bind(this.Configuration);
        }

        public void Dispose()
        {
        }
    }
}
