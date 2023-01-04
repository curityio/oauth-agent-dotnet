namespace IO.Curity.OAuthAgent.Test
{
    using System.Net.Http;
    using System.Net.Http.Json;
    using System.Threading.Tasks;
    using Xunit;
    using IO.Curity.OAuthAgent.Entities;
    using IO.Curity.OAuthAgent.Exceptions;

    [Collection("default")]
    [Trait("Category", "LogoutController")]
    public class LogoutControllerTests
    {
        private readonly IntegrationTestsState state;

        public LogoutControllerTests(IntegrationTestsState state)
        {
            this.state = state;
        }

        [Fact]
        public async Task LogoutController_LogoutUserForMaliciousOrigin_Returns401Response()
        {
            var url = $"{this.state.OAuthAgentBaseUrl}/logout";
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
        public async Task LogoutController_WithoutValidCookies_Returns401Response()
        {
            var url = $"{this.state.OAuthAgentBaseUrl}/logout";
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
        public async Task LogoutController_WithoutInvalidCsrfHeader_Returns401Response()
        {
            var (endResponseData, cookieContainer) = await TestUtils.PerformLogin(this.state);

            var url = $"{this.state.OAuthAgentBaseUrl}/logout";
            using (var handler = new HttpClientHandler { CookieContainer = cookieContainer })
            {
                using (var client = new HttpClient(handler))
                {
                    var request = new HttpRequestMessage(HttpMethod.Post, url);
                    request.Headers.Add("origin", this.state.Configuration.TrustedWebOrigins[0]);
                    request.Headers.Add($"x-{this.state.Configuration.CookieNamePrefix}-csrf", "abc123");
                    
                    var response = await client.SendAsync(request);
                    Assert.Equal(401, ((int)response.StatusCode));

                    var data = await response.Content.ReadFromJsonAsync<ClientErrorResponse>();
                    Assert.Equal("unauthorized_request", data.Code);
                }
            }
        }

        [Fact]
        public async Task LogoutController_WithValidCookiesAndCsrfHeader_ReturnsEndSessionRequestUrl()
        {
            var (endResponseData, cookieContainer) = await TestUtils.PerformLogin(this.state);

            var url = $"{this.state.OAuthAgentBaseUrl}/logout";
            using (var handler = new HttpClientHandler { CookieContainer = cookieContainer })
            {
                using (var client = new HttpClient(handler))
                {
                    var request = new HttpRequestMessage(HttpMethod.Post, url);
                    request.Headers.Add("origin", this.state.Configuration.TrustedWebOrigins[0]);
                    request.Headers.Add($"x-{this.state.Configuration.CookieNamePrefix}-csrf", endResponseData.Csrf);
                    
                    var response = await client.SendAsync(request);
                    response.EnsureSuccessStatusCode();

                    var data = await response.Content.ReadFromJsonAsync<LogoutUserResponse>();
                    Assert.True(data.Url.Length > 0);
                }
            }
        }
    }
}
