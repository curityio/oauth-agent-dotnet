namespace IO.Curity.OAuthAgent.Test
{
    using System.Collections.Generic;
    using System.Net.Http;
    using System.Net.Http.Json;
    using System.Threading.Tasks;
    using Xunit;
    using WireMock.RequestBuilders;
    using WireMock.ResponseBuilders;
    using IO.Curity.OAuthAgent.Exceptions;

    [Collection("default")]
    [Trait("Category", "UserInfoController")]
    public class UserInfoControllerTests
    {
        private readonly IntegrationTestsState state;

        public UserInfoControllerTests(IntegrationTestsState state)
        {
            this.state = state;
        }

        [Fact]
        public async Task UserInfoController_GetFromUntrustedOrigin_Returns401Response()
        {
            var url = $"{this.state.OAuthAgentBaseUrl}/userInfo";
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
        public async Task UserInfoController_WithoutCookies_Returns401Response()
        {
            var url = $"{this.state.OAuthAgentBaseUrl}/userInfo";
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
        public async Task UserInfoController_WithValidCookies_ReturnsExpectedUserInfo()
        {
            var (endResponseData, cookieContainer) = await TestUtils.PerformLogin(this.state);

            var url = $"{this.state.OAuthAgentBaseUrl}/userInfo";
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
                    Assert.Equal("Demo", data["given_name"].ToString());
                    Assert.Equal("User", data["family_name"].ToString());
                }
            }
        }

        [Fact]
        public async Task UserInfoController_WithExpiredAccessToken_Returns401Expired()
        {
            // Make the mock authorization server reject the userinfo request with an expired access token error
            this.state.MockAuthorizationServer.Given(
                Request.Create().WithPath("/oauth/v2/oauth-userinfo").UsingPost()
            )
            .RespondWith(
                Response.Create()
                    .WithStatusCode(401)
                    .WithHeader("content-type", "application-json")
                    .WithBody("{\"error\":\"invalid_token\"}")
            );

            var (endResponseData, cookieContainer) = await TestUtils.PerformLogin(this.state);

            var url = $"{this.state.OAuthAgentBaseUrl}/userInfo";
            using (var handler = new HttpClientHandler { CookieContainer = cookieContainer })
            {
                using (var client = new HttpClient(handler))
                {
                    var request = new HttpRequestMessage(HttpMethod.Get, url);
                    request.Headers.Add("origin", this.state.Configuration.TrustedWebOrigins[0]);

                    var response = await client.SendAsync(request);
                    this.state.RegisterDefaultUserInfoResponseStub();
                    
                    Assert.Equal(401, ((int)response.StatusCode));
                    var data = await response.Content.ReadFromJsonAsync<ClientErrorResponse>();
                    Assert.Equal("token_expired", data.Code);
                }
            }
        }
    }
}
