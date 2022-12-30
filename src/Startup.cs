namespace IO.Curity.OAuthAgent
{
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.Extensions.DependencyInjection;

    public class Startup
    {
        private readonly OAuthAgentConfiguration configuration;

        public Startup(OAuthAgentConfiguration configuration) {
            this.configuration = configuration;
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseRouting();
            app.UseCors();
            app.UseEndpoints(endpoints => {
                endpoints.MapControllers();
            });
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddCors(options => {

                options.AddDefaultPolicy(
                    policy  =>
                    {
                        policy.WithOrigins(this.configuration.TrustedWebOrigins)
                            .AllowAnyHeader()
                            .AllowAnyMethod();
                        policy.AllowCredentials();
                    });
            });

            services.AddControllers();
        }
    }
}
