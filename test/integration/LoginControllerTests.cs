namespace IO.Curity.OAuthAgent.Test
{
    using System.Collections.Generic;
    using System.Linq;
    using System.Net.Http;
    using System.Net.Http.Json;
    using System.Threading.Tasks;
    using Xunit;
    using WireMock.RequestBuilders;
    using WireMock.ResponseBuilders;
    using IO.Curity.OAuthAgent.Exceptions;
    using IO.Curity.OAuthAgent.Entities;

    [Collection("default")]
    [Trait("Category", "LoginController")]
    public class LoginControllerTests
    {
        private readonly IntegrationTestsState state;

        public LoginControllerTests(IntegrationTestsState state)
        {
            this.state = state;
        }

        [Fact]
        public async Task LoginController_StartLoginOptionsWithInvalidOrigin_ReturnsNoCorsHeaders() {

            var url = $"{this.state.OAuthAgentBaseUrl}/login/start";
            using (var client = new HttpClient())
            {
                var request = new HttpRequestMessage(HttpMethod.Options, url);
                request.Headers.Add("origin", "http://malicious-site");
                request.Headers.Add("access-control-request-method", "POST");
                
                var response = await client.SendAsync(request);
                response.EnsureSuccessStatusCode();

                var allowedOrigin = response.Headers.Where(h => h.Key.ToLower() == "access-control-allow-origin");
                Assert.Empty(allowedOrigin);

                var allowedCredentials = response.Headers.Where(h => h.Key.ToLower() == "access-control-allow-credentials");
                Assert.Empty(allowedCredentials);

                var allowedMethods = response.Headers.Where(h => h.Key.ToLower() == "access-control-allow-methods");
                Assert.Empty(allowedMethods);
            }
        }
        
        [Fact]
        public async Task LoginController_StartLoginOptionsWithCorrectOrigin_ReturnsExpectedCorsHeaders() {

            var url = $"{this.state.OAuthAgentBaseUrl}/login/start";
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

        [Fact]
        public async Task LoginController_EndLoginPostForInvalidOrigin_Returns401Response()
        {
            var url = $"{this.state.OAuthAgentBaseUrl}/login/end";
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("origin", "http://malicious-site");

                var requestData = new EndAuthorizationRequest("https://www.example.com");
                var response = await client.PostAsJsonAsync(url, requestData);
                Assert.Equal(401, ((int)response.StatusCode));

                var data = await response.Content.ReadFromJsonAsync<ClientErrorResponse>();
                Assert.Equal("unauthorized_request", data.Code);
            }
        }

        [Fact]
        public async Task LoginController_EndLoginPostForValidOriginWithoutCookies_ReturnsUnauthenticatedResponse()
        {
            var url = $"{this.state.OAuthAgentBaseUrl}/login/end";
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("origin", this.state.Configuration.TrustedWebOrigins[0]);

                var requestData = new EndAuthorizationRequest("https://www.example.local");
                var response = await client.PostAsJsonAsync(url, requestData);
                response.EnsureSuccessStatusCode();
                
                var data = await response.Content.ReadFromJsonAsync<EndAuthorizationResponse>();
                Assert.False(data.Handled);
                Assert.False(data.IsLoggedIn);
                Assert.Empty(data.Csrf);
            }
        }

        [Fact]
        public async Task LoginController_StartLoginPostForInvalidOrigin_Returns401Response()
        {
            var url = $"{this.state.OAuthAgentBaseUrl}/login/start";
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("origin", "http://malicious-site");

                var request = new HttpRequestMessage(HttpMethod.Post, url);
                var response = await client.SendAsync(request);

                Assert.Equal(401, ((int)response.StatusCode));
                var data = await response.Content.ReadFromJsonAsync<ClientErrorResponse>();
                Assert.Equal("unauthorized_request", data.Code);
            }
        }

        [Fact]
        public async Task LoginController_StartLoginForValidOrigin_ReturnsAuthorizationRequestUrl()
        {
            var url = $"{this.state.OAuthAgentBaseUrl}/login/start";
            using (var client = new HttpClient())
            {
                var request = new HttpRequestMessage(HttpMethod.Post, url);
                request.Headers.Add("origin", this.state.Configuration.TrustedWebOrigins[0]);
                
                var response = await client.SendAsync(request);
                response.EnsureSuccessStatusCode();

                var data = await response.Content.ReadFromJsonAsync<StartAuthorizationResponse>();
                Assert.Contains($"client_id={this.state.Configuration.ClientID}", data.AuthorizationRequestUrl);
            }
        }

        [Fact]
        public async Task LoginController_EndLoginWithMaliciousState_ReturnsInvalidRequest()
        {
            var (state, cookieContainer) = await TestUtils.StartLogin(this.state);
            var code = "4a4246d6-b4bd-11ec-b909-0242ac120002";
            var maliciousState = "abc123";

            using (var handler = new HttpClientHandler { CookieContainer = cookieContainer })
            {
                using (var client = new HttpClient(handler))
                {
                    client.DefaultRequestHeaders.Add("origin", this.state.Configuration.TrustedWebOrigins[0]);

                    var endUrl = $"{this.state.OAuthAgentBaseUrl}/login/end";
                    var spaLoginResponseUrl = $"https://www.example.local?code={code}&state={maliciousState}";
                    var requestData = new EndAuthorizationRequest(spaLoginResponseUrl);
                    
                    var response = await client.PostAsJsonAsync(endUrl, requestData);
                    Assert.Equal(400, ((int)response.StatusCode));

                    var data = await response.Content.ReadFromJsonAsync<ClientErrorResponse>();
                    Assert.Equal("invalid_request", data.Code);
                }
            }
        }
        
        [Fact]
        public async Task LoginController_EndLoginValidAuthorizationResponse_ReturnsAuthenticationHandled()
        {
            // Start a login to get the state and the temp login cookie
            var (state, cookieContainer) = await TestUtils.StartLogin(this.state);
            var code = "4a4246d6-b4bd-11ec-b909-0242ac120002";

            using (var handler = new HttpClientHandler { CookieContainer = cookieContainer })
            {
                using (var client = new HttpClient(handler))
                {
                    client.DefaultRequestHeaders.Add("origin", this.state.Configuration.TrustedWebOrigins[0]);

                    // Send the code and state to the OAuth Agent, which will call the authorization server
                    // For tests, Wiremock acts as the authorization server, and any code is accepted
                    var endUrl = $"{this.state.OAuthAgentBaseUrl}/login/end";
                    var spaLoginResponseUrl = $"https://www.example.local?code={code}&state={state}";
                    var requestData = new EndAuthorizationRequest(spaLoginResponseUrl);
                    
                    var response = await client.PostAsJsonAsync(endUrl, requestData);
                    response.EnsureSuccessStatusCode();

                    var data = await response.Content.ReadFromJsonAsync<EndAuthorizationResponse>();
                    Assert.True(data.Handled);
                    Assert.True(data.IsLoggedIn);
                    Assert.True(data.Csrf.Length > 0);
                }
            }
        }

        [Fact]
        public async Task LoginController_EndLoginWithValidCookies_ReturnsAuthenticatedResponse()
        {
            // Perform a login and get cookies
            var (endResponseData, cookieContainer) = await TestUtils.PerformLogin(this.state);

            // Run a page reload with cookies
            using (var handler = new HttpClientHandler { CookieContainer = cookieContainer })
            {
                using (var client = new HttpClient(handler))
                {
                    client.DefaultRequestHeaders.Add("origin", this.state.Configuration.TrustedWebOrigins[0]);

                    var endUrl = $"{this.state.OAuthAgentBaseUrl}/login/end";
                    var spaLoginResponseUrl = $"https://www.example.local";
                    var requestData = new EndAuthorizationRequest(spaLoginResponseUrl);
                    
                    var response = await client.PostAsJsonAsync(endUrl, requestData);
                    response.EnsureSuccessStatusCode();

                    var data = await response.Content.ReadFromJsonAsync<EndAuthorizationResponse>();
                    Assert.False(data.Handled);
                    Assert.True(data.IsLoggedIn);
                    Assert.True(data.Csrf.Length > 0);
                }
            }
        }

        [Fact]
        public async Task LoginController_EndLoginWithIncorrectlyConfiguredClientSecret_Returns400()
        {
            var (state, cookieContainer) = await TestUtils.StartLogin(this.state);
            var code = "4a4246d6-b4bd-11ec-b909-0242ac120002";

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

            using (var handler = new HttpClientHandler { CookieContainer = cookieContainer })
            {
                using (var client = new HttpClient(handler))
                {
                    client.DefaultRequestHeaders.Add("origin", this.state.Configuration.TrustedWebOrigins[0]);

                    var endUrl = $"{this.state.OAuthAgentBaseUrl}/login/end";
                    var spaLoginResponseUrl = $"https://www.example.local?code={code}&state={state}";
                    var requestData = new EndAuthorizationRequest(spaLoginResponseUrl);
                    
                    var response = await client.PostAsJsonAsync(endUrl, requestData);
                    this.state.RegisterDefaultTokenResponseStub();

                    Assert.Equal(400, ((int)response.StatusCode));
                    var data = await response.Content.ReadFromJsonAsync<ClientErrorResponse>();
                    Assert.Equal("authorization_error", data.Code);
                }
            }
        }

        [Fact]
        public async Task LoginController_EndLoginWithInvalidScopeDueToMisconfiguredClient_Returns400Error()
        {
            var (state, cookieContainer) = await TestUtils.StartLogin(this.state);

            using (var handler = new HttpClientHandler { CookieContainer = cookieContainer })
            {
                using (var client = new HttpClient(handler))
                {
                    client.DefaultRequestHeaders.Add("origin", this.state.Configuration.TrustedWebOrigins[0]);

                    var endUrl = $"{this.state.OAuthAgentBaseUrl}/login/end";
                    var spaLoginResponseUrl = $"https://www.example.local?error=invalid_scope&state={state}";
                    var requestData = new EndAuthorizationRequest(spaLoginResponseUrl);
                    
                    var response = await client.PostAsJsonAsync(endUrl, requestData);
                    Assert.Equal(400, ((int)response.StatusCode));

                    var data = await response.Content.ReadFromJsonAsync<ClientErrorResponse>();
                    Assert.Equal("invalid_scope", data.Code);
                }
            }
        }

        [Fact]
        public async Task LoginController_EndLoginOnFrontChannelWithLoginRequired_Returns401ForExpiryRelatedErrors()
        {
            var parameters = new List<ExtraParams>
            {
                new ExtraParams("prompt", "none")
            };
            var (state, cookieContainer) = await TestUtils.StartLogin(this.state, new StartAuthorizationParameters(parameters));

            using (var handler = new HttpClientHandler { CookieContainer = cookieContainer })
            {
                using (var client = new HttpClient(handler))
                {
                    client.DefaultRequestHeaders.Add("origin", this.state.Configuration.TrustedWebOrigins[0]);

                    var endUrl = $"{this.state.OAuthAgentBaseUrl}/login/end";
                    var spaLoginResponseUrl = $"https://www.example.local?error=login_required&state={state}";
                    var requestData = new EndAuthorizationRequest(spaLoginResponseUrl);
                    
                    var response = await client.PostAsJsonAsync(endUrl, requestData);
                    Assert.Equal(401, ((int)response.StatusCode));

                    var data = await response.Content.ReadFromJsonAsync<ClientErrorResponse>();
                    Assert.Equal("login_required", data.Code);
                }
            }
        }
    }
}
