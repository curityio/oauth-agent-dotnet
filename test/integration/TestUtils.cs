namespace IO.Curity.OAuthAgent.Test
{
    using System;
    using System.Collections.Generic;
    using System.Net;
    using System.Net.Http;
    using System.Net.Http.Json;
    using System.Threading.Tasks;
    using System.Web;
    using IO.Curity.OAuthAgent.Entities;

    public class TestUtils
    {
        /*
         * Start a login and return the temp cookie, for a test to use
         */
        public static async Task<(string, CookieContainer)> StartLogin(IntegrationTestsState testState, StartAuthorizationParameters parameters = null)
        {
            var cookieContainer = new CookieContainer();
            using (var handler = new HttpClientHandler { CookieContainer = cookieContainer })
            {
                using (var client = new HttpClient(handler))
                {
                    client.DefaultRequestHeaders.Add("origin", testState.Configuration.TrustedWebOrigins[0]);

                    var url = $"{testState.OAuthAgentBaseUrl}/login/start";
                    var request = new HttpRequestMessage(HttpMethod.Post, url);

                    var requestData = parameters ?? new StartAuthorizationParameters(new List<ExtraParams>());
                    var response = await client.PostAsJsonAsync<StartAuthorizationParameters>(url, requestData);
                    response.EnsureSuccessStatusCode();

                    var responseData = await response.Content.ReadFromJsonAsync<StartAuthorizationResponse>();
                    var data = HttpUtility.ParseQueryString(new Uri(responseData.AuthorizationRequestUrl).Query);
                    return (data["state"], cookieContainer);
                }
            }
        }

        /*
         * End a login and return tokens in cookies, for a test to use
         */
        public static async Task<(EndAuthorizationResponse, CookieContainer)> PerformLogin(IntegrationTestsState testState)
        {
            var (state, cookieContainer) = await TestUtils.StartLogin(testState);
            var code = "4a4246d6-b4bd-11ec-b909-0242ac120002";

            using (var handler = new HttpClientHandler { CookieContainer = cookieContainer })
            {
                using (var client = new HttpClient(handler))
                {
                    client.DefaultRequestHeaders.Add("origin", testState.Configuration.TrustedWebOrigins[0]);

                    var endUrl = $"{testState.OAuthAgentBaseUrl}/login/end";
                    var spaLoginResponseUrl = $"https://www.example.local?code={code}&state={state}";
                    var requestData = new EndAuthorizationRequest(spaLoginResponseUrl);
                    var response = await client.PostAsJsonAsync(endUrl, requestData);

                    var responseData = await response.Content.ReadFromJsonAsync<EndAuthorizationResponse>();
                    return (responseData, cookieContainer);
                }
            }
        }
    }
}
