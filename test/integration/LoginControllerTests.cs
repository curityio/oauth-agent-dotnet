namespace IO.Curity.OAuthAgent.Test
{
    using System.Collections.Generic;
    using System.Linq;
    using System.Net.Http;
    using System.Net.Http.Json;
    using System.Threading.Tasks;
    using Xunit;
    using IO.Curity.OAuthAgent.Entities;

    /*
     * Tests against the login controller operations
     */
    [Collection("default")]
    [Trait("Category", "LoginController")]
    public class LoginControllerTests
    {
        private readonly IntegrationTestsState state;
        private readonly string baseUrl;

        public LoginControllerTests(IntegrationTestsState state)
        {
            this.state = state;
            this.baseUrl = "http://localhost:8080/oauth-agent";
        }

        [Fact]
        public async Task LoginController_StartLoginOptionsWithInvalidOrigin_ReturnsNoCorsHeaders() {

            var url = $"{this.baseUrl}/login/start";
            using (var client = new HttpClient())
            {
                var request = new HttpRequestMessage(HttpMethod.Options, url);
                request.Headers.Add("origin", "http://malicious-site");
                request.Headers.Add("Access-Control-Request-Method", "POST");
                
                var response = await client.SendAsync(request);
                response.EnsureSuccessStatusCode();

                var allowedOrigin = response.Headers.Where(h => h.Key.ToLower() == "access-control-allow-origin");
                Assert.Equal(0, allowedOrigin.Count());

                var allowedCredentials = response.Headers.Where(h => h.Key.ToLower() == "access-control-allow-credentials");
                Assert.Equal(0, allowedCredentials.Count());

                var allowedMethods = response.Headers.Where(h => h.Key.ToLower() == "access-control-allow-methods");
                Assert.Equal(0, allowedMethods.Count());
            }
        }
        
        [Fact]
        public async Task LoginController_StartLoginOptionsWithCorrectOrigin_ReturnsExpectedCorsHeaders() {

            var url = $"{this.baseUrl}/login/start";
            using (var client = new HttpClient())
            {
                var request = new HttpRequestMessage(HttpMethod.Options, url);
                request.Headers.Add("origin", this.state.Configuration.TrustedWebOrigins[0]);
                request.Headers.Add("access-control-request-method", "POST");
                
                var response = await client.SendAsync(request);
                response.EnsureSuccessStatusCode();

                var allowedOrigin = response.Headers.First(h => h.Key.ToLower() == "access-control-allow-origin");
                Assert.Equal("http://www.example.local", allowedOrigin.Value.First());

                var allowedCredentials = response.Headers.First(h => h.Key.ToLower() == "access-control-allow-credentials");
                Assert.Equal("true", allowedCredentials.Value.First());

                var allowedMethods = response.Headers.First(h => h.Key.ToLower() == "access-control-allow-methods");
                Assert.Equal("POST", allowedMethods.Value.First());
            }
        }

        [Fact(Skip="Not implemented")]
        public async Task LoginController_EndLoginPostForInvalidOrigin_Returns401Response()
        {
            var url = $"{this.baseUrl}/login/end";
            using (var client = new HttpClient())
            {
                var request = new HttpRequestMessage(HttpMethod.Post, url);
                request.Headers.Add("origin", "http://malicious-site");

                var requestData = new EndAuthorizationRequest("https://www.example.com");
                var response = await client.PostAsJsonAsync(url, requestData);
                Assert.Equal(401, ((int)response.StatusCode));
            }
        }

        [Fact]
        public async Task LoginController_EndLoginPostForValidOriginWithoutCookies_ReturnsUnauthenticatedResponse()
        {
            var url = $"{this.baseUrl}/login/end";
            using (var client = new HttpClient())
            {
                var request = new HttpRequestMessage(HttpMethod.Post, url);
                request.Headers.Add("origin", this.state.Configuration.TrustedWebOrigins[0]);

                var requestData = new EndAuthorizationRequest("https://www.example.com");
                var response = await client.PostAsJsonAsync(url, requestData);
                response.EnsureSuccessStatusCode();
                
                var data = await response.Content.ReadFromJsonAsync<EndAuthorizationResponse>();
                Assert.False(data.Handled);
                Assert.False(data.IsLoggedIn);
                Assert.Empty(data.Csrf);
            }
        }

        [Fact(Skip = "Not implemented")]
        public async Task LoginController_StartLoginPostForInvalidOrigin_Returns401Response()
        {
            var url = $"{this.baseUrl}/login/end";
            using (var client = new HttpClient())
            {
                var request = new HttpRequestMessage(HttpMethod.Post, url);
                request.Headers.Add("origin", "http://malicious-site");
                
                var response = await client.SendAsync(request);
                Assert.Equal(401, ((int)response.StatusCode));
            }
        }

        [Fact]
        public async Task LoginController_StartLoginForValidOrigin_ReturnsAuthorizationRequestUrl()
        {
            var url = $"{this.baseUrl}/login/start";
            using (var client = new HttpClient())
            {
                var request = new HttpRequestMessage(HttpMethod.Post, url);
                request.Headers.Add("origin", this.state.Configuration.TrustedWebOrigins[0]);
                
                var response = await client.SendAsync(request);
                response.EnsureSuccessStatusCode();

                var data = await response.Content.ReadFromJsonAsync<StartAuthorizationResponse>();
                Assert.True(data.AuthorizationRequestUrl.Length > 0);
            }
        }

        [Fact(Skip = "Not implemented")]
        public async Task LoginController_EndLoginWithCodeResponseAndValidCookies_ReturnsAuthenticationHandled()
        {
        }

        [Fact(Skip = "Not implemented")]
        public async Task LoginController_EndLoginWithMaliciousState_ReturnsInvalidRequest()
        {
        }

        [Fact(Skip = "Not implemented")]
        public async Task LoginController_EndLoginWithValidCookies_ReturnsAuthenticatedState()
        {
        }

        [Fact(Skip = "Not implemented")]
        public async Task LoginController_EndLoginWithIncorrectlyConfiguredClientSecret_Returns400()
        {
        }

        [Fact(Skip = "Not implemented")]
        public async Task LoginController_StartLoginWithMisconfiguredClient_ReturnsExpectedError()
        {
        }

        [Fact(Skip = "Not implemented")]
        public async Task LoginController_StartLoginWithParameters_Returns401ForExpiredErrors()
        {
        }
    }
}