using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;

namespace OAuthAgent
{
    public class Program
    {
        public static void Main(string[] args)
        {
            BuildWebHost().Run();
        }

        private static IWebHost BuildWebHost()
        {
            int port = 8080;
            return new WebHostBuilder()

                .UseKestrel(options =>
                {
                    options.Listen(System.Net.IPAddress.Any, port, listenOptions =>
                    {
                    });
                })

                .UseStartup<Startup>()
                .Build();
        }

    }
}
