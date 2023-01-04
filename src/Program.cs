namespace IO.Curity.OAuthAgent
{
    using System.IO;
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.Extensions.Configuration;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.Hosting;
    using Microsoft.Extensions.Logging;

    public class Program
    {
        public static void Main(string[] args)
        {
            Program.BuildWebHost().Run();
        }

        /*
         * The dev settings file is used only for development overrides, and not deployed
         */
        private static IWebHost BuildWebHost()
        {
            var configurationRoot = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: true)
                .AddJsonFile("appsettings-dev.json", optional: true)
                .Build();

            var configuration = new OAuthAgentConfiguration();
            if (File.Exists("appsettings-dev.json"))
            {
                configurationRoot.GetSection("OAuthAgentConfiguration")
                    .Bind(configuration);
            }
            else
            {
                configuration.FromEnvironment();
            }

            return new WebHostBuilder()
                .ConfigureServices(services =>
                {
                    services.AddSingleton(configuration);
                })
                .ConfigureLogging(loggingBuilder => {
                    
                    loggingBuilder.ClearProviders();
                    loggingBuilder.AddConfiguration(configurationRoot.GetSection("Logging"));
                    loggingBuilder.AddConsole();
                })
                .UseKestrel(options =>
                {
                    options.Listen(System.Net.IPAddress.Any, configuration.Port, listenOptions =>
                    {
                        if (!string.IsNullOrWhiteSpace(configuration.ServerCertPath))
                        {
                            listenOptions.UseHttps(configuration.ServerCertPath, configuration.ServerCertPassword);
                        }
                    });
                })
                .UseStartup<Startup>()
                .Build();
        }

    }
}
