namespace IO.Curity.OAuthAgent.Test
{
    using System;
    using System.IO;
    using Microsoft.Extensions.Configuration;
    using WireMock.RequestBuilders;
    using WireMock.ResponseBuilders;
    using WireMock.Server;
    using Xunit;

    [CollectionDefinition("default")]
    public class IntegrationTestsState : IDisposable
    {
        public string OAuthAgentBaseUrl { get; private set; }

        public OAuthAgentConfiguration Configuration { get; private set; }

        public WireMockServer MockAuthorizationServer { get; private set; }

        public IntegrationTestsState()
        {
            this.MockAuthorizationServer = WireMockServer.Start(8443);
            this.RegisterDefaultTokenResponseStub();
            this.RegisterDefaultUserInfoResponseStub();

            this.OAuthAgentBaseUrl = "http://api.example.local:8080/oauth-agent";
            
            var configFilePath = Path.Combine(System.IO.Directory.GetCurrentDirectory(), "../../../../../appsettings-dev.json");
            
            var configurationRoot = new ConfigurationBuilder()
                .AddJsonFile(configFilePath)
                .Build();

            this.Configuration = new OAuthAgentConfiguration();
            configurationRoot.GetSection("OAuthAgentConfiguration").Bind(this.Configuration);
        }

        public void Dispose()
        {
            this.MockAuthorizationServer.Stop();
        }

        public void RegisterDefaultTokenResponseStub()
        {
            this.MockAuthorizationServer.Given(
                Request.Create().WithPath("/oauth/v2/oauth-token").UsingPost()
            )
            .RespondWith(
                Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("content-type", "application-json")
                    .WithBody("{\"access_token\":\"_0XBPWQQ_2fe74f4b-68b9-4128-8e75-d738b34dbce2\",\"refresh_token\":\"_1XBPWQQ_ae0ea3f2-a0bc-48e2-a216-cb8b650670cd\",\"id_token\":\"eyJraWQiOiI2NTU4NTI4NzgiLCJ4NXQiOiJOWGRLQ1NWMjlTQ2k4c05Nb1F1ZzRpY093bWsiLCJhbGciOiJSUzI1NiJ9.eyJleHAiOjE2ODkyNDE4NzgsIm5iZiI6MTY4OTIzODI3OCwianRpIjoiMTY1NzE0NmItNWYzMC00YTkwLWIwOWItNTE0NzZiNWZkZTYzIiwiaXNzIjoiaHR0cDovL2xvZ2luLmV4YW1wbGUubG9jYWw6ODQ0My9vYXV0aC92Mi9vYXV0aC1hbm9ueW1vdXMiLCJhdWQiOlsic3BhLWNsaWVudCIsImFwaS5leGFtcGxlLmxvY2FsIl0sInN1YiI6IjBhYmQwYjE2YjMwOWEzYTAzNGFmODQ5NGFhMDA5MmFhNDI4MTNlNjM1ZjE5NGM3OTVkZjUwMDZkYjkwNzQzZTgiLCJhdXRoX3RpbWUiOjE2ODkyMzgyNzgsImlhdCI6MTY4OTIzODI3OCwicHVycG9zZSI6ImlkIiwiYXRfaGFzaCI6IkliZTJ4ZXVNaTZ2QkJPazFEbFA5Y2ciLCJhY3IiOiJ1cm46c2U6Y3VyaXR5OmF1dGhlbnRpY2F0aW9uOmh0bWwtZm9ybTpVc2VybmFtZS1QYXNzd29yZCIsImRlbGVnYXRpb25faWQiOiIxMmY0ODM1ZS1lZTQ3LTQ3YjYtYjYzOC04NTc5Y2NmMTNhZWIiLCJzX2hhc2giOiJuUDBJMDF5VWRtdmZEQkVGZXZHS3BRIiwiYXpwIjoic3BhLWNsaWVudCIsImFtciI6InVybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246aHRtbC1mb3JtOlVzZXJuYW1lLVBhc3N3b3JkIiwic2lkIjoiUHQyTndFRWQ3eUxhdFkwNSJ9.c3nYUjQeUFOiI29ud-DUDLkhv8L3vHtyCZdLMeGarahLbvLlVtwB_NCtglEa8bnCfCNZt9uP_RHXFsTYJDj9o6qXPF2fukIc05hPXqTWd1WoXjIf6_SUFC4bF9UWBLMumX4v0GZQ7Ps_VG2OGKlzUgaw1C9ljymh3JTUg2WlfvNbgGcdd4rJsPFZbp0kJOx-rgPwlvlCQxHak2NAJu1MXpLYSwq0Cbex7i492bq0_5yeNwFsCbEG8nRAG1YlCr7T5RGm_UGuKhmhLyG-3HKG7y2ssFgw47e8ogW7y6JCOANPuVsZfgo0vjNRqIEjOKvEhhoYa265BC5iLiZkoY99EA\"}")
            );
        }

        public void RegisterDefaultUserInfoResponseStub()
        {
            this.MockAuthorizationServer.Given(
                Request.Create().WithPath("/oauth/v2/oauth-userinfo").UsingPost()
            )
            .RespondWith(
                Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("content-type", "application-json")
                    .WithBody("{\"sub\":\"0abd0b16b309a3a034af8494aa0092aa42813e635f194c795df5006db90743e8\", \"preferred_username\":\"demouser\", \"given_name\":\"Demo\", \"family_name\":\"User\"}")
            );
        }
    }
}
