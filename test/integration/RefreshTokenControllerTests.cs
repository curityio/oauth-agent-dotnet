namespace IO.Curity.OAuthAgent.Test
{
    using System.Linq;
    using System.Net.Http;
    using System.Net.Http.Json;
    using System.Threading.Tasks;
    using Xunit;
    using WireMock.RequestBuilders;
    using WireMock.ResponseBuilders;
    using IO.Curity.OAuthAgent.Exceptions;

    /*
     * Test the login controller operations
     */
    [Collection("default")]
    [Trait("Category", "RefreshTokenController")]
    public class RefreshTokenControllerTests
    {
        private readonly IntegrationTestsState state;

        public RefreshTokenControllerTests(IntegrationTestsState state)
        {
            this.state = state;
        }

        [Fact]
        public async Task RefreshController_PostFromUntrustedOrigin_Returns401Response()
        {
            var url = $"{this.state.OAuthAgentBaseUrl}/refresh";
            using (var client = new HttpClient())
            {
                var request = new HttpRequestMessage(HttpMethod.Post, url);
                request.Headers.Add("origin", "http://malicious-site");

                var response = await client.SendAsync(request);
                Assert.Equal(401, ((int)response.StatusCode));

                var data = await response.Content.ReadFromJsonAsync<ClientErrorResponse>();
                Assert.Equal("unauthorized_request", data.Code);
            }
        }

        [Fact]
        public async Task RefreshController_PostWithoutValidCookies_Returns401Response()
        {
            var url = $"{this.state.OAuthAgentBaseUrl}/refresh";
            using (var client = new HttpClient())
            {
                var request = new HttpRequestMessage(HttpMethod.Post, url);
                request.Headers.Add("origin", this.state.Configuration.TrustedWebOrigins[0]);

                var response = await client.SendAsync(request);
                Assert.Equal(401, ((int)response.StatusCode));

                var data = await response.Content.ReadFromJsonAsync<ClientErrorResponse>();
                Assert.Equal("unauthorized_request", data.Code);
            }
        }

        [Fact]
        public async Task RefreshController_WithMissingCsrfHeader_ReturnsEndSessionRequestUrl()
        {
            var (endResponseData, cookieContainer) = await TestUtils.PerformLogin(this.state);

            var url = $"{this.state.OAuthAgentBaseUrl}/refresh";
            using (var handler = new HttpClientHandler { CookieContainer = cookieContainer })
            {
                using (var client = new HttpClient(handler))
                {
                    var request = new HttpRequestMessage(HttpMethod.Post, url);
                    request.Headers.Add("origin", this.state.Configuration.TrustedWebOrigins[0]);
                    
                    var response = await client.SendAsync(request);
                    Assert.Equal(401, ((int)response.StatusCode));

                    var data = await response.Content.ReadFromJsonAsync<ClientErrorResponse>();
                    Assert.Equal("unauthorized_request", data.Code);
                }
            }
        }
        
        [Fact]
        public async Task RefreshController_WithValidCookiesAndCsrfHeader_ReturnsUpdatedCookies()
        {
            var (endResponseData, cookieContainer) = await TestUtils.PerformLogin(this.state);

            var url = $"{this.state.OAuthAgentBaseUrl}/refresh";
            using (var handler = new HttpClientHandler { CookieContainer = cookieContainer })
            {
                using (var client = new HttpClient(handler))
                {
                    var request = new HttpRequestMessage(HttpMethod.Post, url);
                    request.Headers.Add("origin", this.state.Configuration.TrustedWebOrigins[0]);
                    request.Headers.Add($"x-{this.state.Configuration.CookieNamePrefix}-csrf", endResponseData.Csrf);
                    
                    var response = await client.SendAsync(request);
                    response.EnsureSuccessStatusCode();

                    var cookies = response.Headers.GetValues("set-cookie").ToList();
                    Assert.NotEmpty(cookies);
                    Assert.True(cookies.First().Length > 0);
                }
            }
        }

        [Fact]
        public async Task RefreshController_WithWrongClientSecretConfigured_Returns400Error()
        {
            var (endResponseData, cookieContainer) = await TestUtils.PerformLogin(this.state);

            // On the next token request, make the mock authorization server reject token issuing with incorrect client secret behavior
            this.state.MockAuthorizationServer.Given(
                Request.Create().WithPath("/oauth/v2/oauth-token").UsingPost()
            )
            .RespondWith(
                Response.Create()
                    .WithStatusCode(400)
                    .WithHeader("content-type", "application-json")
                    .WithBody("{\"error\":\"invalid_client\"}")
            );

            var url = $"{this.state.OAuthAgentBaseUrl}/refresh";
            using (var handler = new HttpClientHandler { CookieContainer = cookieContainer })
            {
                using (var client = new HttpClient(handler))
                {
                    var request = new HttpRequestMessage(HttpMethod.Post, url);
                    request.Headers.Add("origin", this.state.Configuration.TrustedWebOrigins[0]);
                    request.Headers.Add($"x-{this.state.Configuration.CookieNamePrefix}-csrf", endResponseData.Csrf);
                    
                    var response = await client.SendAsync(request);
                    this.state.RegisterDefaultTokenResponseStub();

                    Assert.Equal(400, ((int)response.StatusCode));
                    var data = await response.Content.ReadFromJsonAsync<ClientErrorResponse>();
                    Assert.Equal("authorization_error", data.Code);
                }
            }

            this.state.MockAuthorizationServer.ResetScenario("TEMP");
        }

        [Fact]
        public async Task RefreshController_WithExpiredRefreshToken_ReturnsInvalidGrantErrorWithClearedCookies()
        {
            var (endResponseData, cookieContainer) = await TestUtils.PerformLogin(this.state);
            
            // On the next token request, make the mock authorization server reject the userinfo request with an expired refresh token error
            this.state.MockAuthorizationServer.Given(
                Request.Create().WithPath("/oauth/v2/oauth-token").UsingPost()
            )
            .RespondWith(
                Response.Create()
                    .WithStatusCode(401)
                    .WithHeader("content-type", "application-json")
                    .WithBody("{\"error\":\"invalid_grant\"}")
            );

            var url = $"{this.state.OAuthAgentBaseUrl}/refresh";
            using (var handler = new HttpClientHandler { CookieContainer = cookieContainer })
            {
                using (var client = new HttpClient(handler))
                {
                    var request = new HttpRequestMessage(HttpMethod.Post, url);
                    request.Headers.Add("origin", this.state.Configuration.TrustedWebOrigins[0]);
                    request.Headers.Add($"x-{this.state.Configuration.CookieNamePrefix}-csrf", endResponseData.Csrf);
                    
                    var response = await client.SendAsync(request);
                    this.state.RegisterDefaultTokenResponseStub();

                    Assert.Equal(401, ((int)response.StatusCode));
                    var data = await response.Content.ReadFromJsonAsync<ClientErrorResponse>();
                    Assert.Equal("session_expired", data.Code);
                }
            }
        }
    }
}
