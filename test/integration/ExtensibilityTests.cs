namespace IO.Curity.OAuthAgent.Test
{
    using System.Collections.Generic;
    using System.Net.Http;
    using System.Net.Http.Json;
    using System.Text.Json.Nodes;
    using System.Threading.Tasks;
    using System.Web;
    using Xunit;
    using IO.Curity.OAuthAgent.Entities;

    [Collection("default")]
    [Trait("Category", "Extensibility")]
    public class ExtensibilityTests
    {
        private readonly IntegrationTestsState state;

        public ExtensibilityTests(IntegrationTestsState state)
        {
            this.state = state;
        }

        [Fact]
        public async Task Extensibility_StartLoginWithSingleCustomParameter_UpdatesUrlCorrectly()
        {
            var requestData = new StartAuthorizationParameters(new List<ExtraParams>
            {
                new ExtraParams("ui_locales", "fr")
            });

            var url = $"{this.state.OAuthAgentBaseUrl}/login/start";
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("origin", this.state.Configuration.TrustedWebOrigins[0]);
                
                var response = await client.PostAsJsonAsync(url, requestData);
                response.EnsureSuccessStatusCode();

                var data = await response.Content.ReadFromJsonAsync<StartAuthorizationResponse>();
                System.Console.WriteLine(data.AuthorizationRequestUrl);
                Assert.Contains($"{requestData.ExtraParams[0].Key}={requestData.ExtraParams[0].Value}", data.AuthorizationRequestUrl);
            }
        }

        [Fact]
        public async Task Extensibility_StartLoginWithComplexParameters_UpdatesUrlCorrectly()
        {
            var claims = new JsonObject
            {
                ["id_token"] = new JsonObject
                {
                    ["acr"] = new JsonObject
                    {
                        ["essential"] = true,
                        ["values"] = new JsonArray
                        {
                            "urn:se:curity:authentication:html-form:htmlform1"
                        }

                    }
                }
            };

            var requestData = new StartAuthorizationParameters(new List<ExtraParams>
            {
                new ExtraParams("ui_locales", "fr"),
                new ExtraParams("claims", claims.ToJsonString())
            });

            var url = $"{this.state.OAuthAgentBaseUrl}/login/start";
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("origin", this.state.Configuration.TrustedWebOrigins[0]);
                
                var response = await client.PostAsJsonAsync(url, requestData);
                response.EnsureSuccessStatusCode();

                var data = await response.Content.ReadFromJsonAsync<StartAuthorizationResponse>();
                requestData.ExtraParams.ForEach(p => {
                    Assert.Contains($"{p.Key}={HttpUtility.UrlEncode(p.Value)}", data.AuthorizationRequestUrl);
                });
            }
        }
    }
}
