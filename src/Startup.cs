namespace IO.Curity.OAuthAgent
{
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.Extensions.Configuration;
    using Microsoft.Extensions.DependencyInjection;

    public class Startup
    {
        public IWebHostEnvironment Environment {get; }
        public IConfiguration Configuration {get; }

        public Startup(IWebHostEnvironment environment, IConfiguration config) {
            Environment = environment;
            Configuration = config;
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseRouting();
            app.UseEndpoints(endpoints => {
                endpoints.MapControllers();
            });
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();
        }
    }
}
