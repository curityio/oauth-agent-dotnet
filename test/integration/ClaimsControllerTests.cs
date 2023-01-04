namespace IO.Curity.OAuthAgent.Test
{
    using System.Collections.Generic;
    using System.Net.Http;
    using System.Net.Http.Json;
    using System.Threading.Tasks;
    using Xunit;
    using IO.Curity.OAuthAgent.Exceptions;

    [Collection("default")]
    [Trait("Category", "ClaimsController")]
    public class ClaimsControllerTests
    {
        private readonly IntegrationTestsState state;

        public ClaimsControllerTests(IntegrationTestsState state)
        {
            this.state = state;
        }

        [Fact]
        public async Task ClaimsController_GetFromUntrustedOrigin_Returns401Response()
        {
            var url = $"{this.state.OAuthAgentBaseUrl}/claims";
            using (var client = new HttpClient())
            {
                var request = new HttpRequestMessage(HttpMethod.Get, url);
                request.Headers.Add("origin", "http://malicious-site");

                var response = await client.SendAsync(request);
                Assert.Equal(401, ((int)response.StatusCode));

                var data = await response.Content.ReadFromJsonAsync<ClientErrorResponse>();
                Assert.Equal("unauthorized_request", data.Code);
            }
        }

        [Fact]
        public async Task ClaimsController_WithoutCookies_Returns401Response()
        {
            var url = $"{this.state.OAuthAgentBaseUrl}/claims";
            using (var client = new HttpClient())
            {
                var request = new HttpRequestMessage(HttpMethod.Get, url);
                request.Headers.Add("origin", this.state.Configuration.TrustedWebOrigins[0]);

                var response = await client.SendAsync(request);
                Assert.Equal(401, ((int)response.StatusCode));

                var data = await response.Content.ReadFromJsonAsync<ClientErrorResponse>();
                Assert.Equal("unauthorized_request", data.Code);
            }
        }

        [Fact]
        public async Task ClaimsController_WithValidCookies_ReturnsIdTokernClaims()
        {
            var (endResponseData, cookieContainer) = await TestUtils.PerformLogin(this.state);

            var url = $"{this.state.OAuthAgentBaseUrl}/claims";
            using (var handler = new HttpClientHandler { CookieContainer = cookieContainer })
            {
                using (var client = new HttpClient(handler))
                {
                    var request = new HttpRequestMessage(HttpMethod.Get, url);
                    request.Headers.Add("origin", this.state.Configuration.TrustedWebOrigins[0]);

                    var response = await client.SendAsync(request);
                    response.EnsureSuccessStatusCode();

                    var data = await response.Content.ReadFromJsonAsync<Dictionary<string, object>>();
                    Assert.NotEmpty(data);
                    Assert.True(data["auth_time"].ToString().Length > 0);
                }
            }
        }
    }
}
