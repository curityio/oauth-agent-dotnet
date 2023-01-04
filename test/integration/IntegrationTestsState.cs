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
            this.RegisterStubs();

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

        private void RegisterStubs()
        {
            // A default mapping to return tokens from the token endpoint
            this.MockAuthorizationServer.Given(
                Request.Create().WithPath("/oauth/v2/oauth-token").UsingPost()
            )
            .AtPriority(10)
            .RespondWith(
                Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("content-type", "application-json")
                    .WithBody("{\"access_token\":\"_0XBPWQQ_2fe74f4b-68b9-4128-8e75-d738b34dbce2\",\"refresh_token\":\"_1XBPWQQ_ae0ea3f2-a0bc-48e2-a216-cb8b650670cd\",\"id_token\":\"eyJraWQiOiItMjE0NTM1NzY1NSIsIng1dCI6IjB3ZUtaQ1FieWx6dk5LMG5WZHJGQnZaVmJvQSIsImFsZyI6IlJTMjU2In0.eyJleHAiOjE2NDkxNjQ1NzgsIm5iZiI6MTY0OTE2MDk3OCwianRpIjoiNzg2ZDIzMDUtN2EwZi00YmVlLTgzOTEtMTRlZjY4NGI5MjI2IiwiaXNzIjoiaHR0cDovL2xvZ2luLmV4YW1wbGUubG9jYWw6ODQ0My9vYXV0aC92Mi9vYXV0aC1hbm9ueW1vdXMiLCJhdWQiOiJzcGEtY2xpZW50Iiwic3ViIjoiMGFiZDBiMTZiMzA5YTNhMDM0YWY4NDk0YWEwMDkyYWE0MjgxM2U2MzVmMTk0Yzc5NWRmNTAwNmRiOTA3NDNlOCIsImF1dGhfdGltZSI6MTY0OTE2MDk3OCwiaWF0IjoxNjQ5MTYwOTc4LCJwdXJwb3NlIjoiaWQiLCJhdF9oYXNoIjoiNXdqc2s4em9hd0xVLTBtSXBlQzhzQSIsImFjciI6InVybjpzZTpjdXJpdHk6YXV0aGVudGljYXRpb246aHRtbC1mb3JtOlVzZXJuYW1lLVBhc3N3b3JkIiwiZGVsZWdhdGlvbl9pZCI6ImY5ODM4ZmNkLWEyZGEtNDMwMS04NTMyLWFhNmM4NjhhYTY0OCIsInNfaGFzaCI6InlySEF3b1ZaZnFjaWNjQXVNNEF1U2ciLCJhenAiOiJzcGEtY2xpZW50IiwiYW1yIjoidXJuOnNlOmN1cml0eTphdXRoZW50aWNhdGlvbjpodG1sLWZvcm06VXNlcm5hbWUtUGFzc3dvcmQiLCJzaWQiOiJiZkZBeFlEZFVmRGxramNEIn0.K8X8AdkKvEBJIQSxOiNTuZSHoWRtW-Wjd7e0lisMl3fUuO9EKxem8AlRD5fP_KvqevqNEhUHRRsYBJg8k4swexqtFnd-q22L_Q8CjyuDLfTj0_eUWXkZCxND6FFv0FzoYBOAIy1OheCPr_lcyyVAKfM34PujDm2Z7nUETxv7AfDMYcdjJO5mKFKFfXi0YineAl2JD1uQ0gaOvK8z-4O5wxl6rJRmUOn6DT-OLEHvR6nhagmZCohJbGCtQ0sMjl6l7hxt5npF5kmK1uoqfnOjznzgyaM-hxItdLEHP-FznLsa63g2sIJaK0ZbJCdZ2HzbaXo4-VAP4SCBDZSGMgDVtg\"}")
            );

            // A default mapping to return userinfo from the userinfo endpoint
            this.MockAuthorizationServer.Given(
                Request.Create().WithPath("/oauth/v2/oauth-userinfo").UsingPost()
            )
            .AtPriority(10)
            .RespondWith(
                Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("content-type", "application-json")
                    .WithBody("{\"sub\":\"0abd0b16b309a3a034af8494aa0092aa42813e635f194c795df5006db90743e8\", \"preferred_username\":\"demouser\", \"given_name\":\"Demo\", \"family_name\":\"User\"}")
            );
        }
    }
}
