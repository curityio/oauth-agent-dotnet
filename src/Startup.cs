namespace IO.Curity.OAuthAgent
{
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.Extensions.DependencyInjection;
    using IO.Curity.OAuthAgent.Exceptions;
    using IO.Curity.OAuthAgent.Utilities;

    public class Startup
    {
        private readonly OAuthAgentConfiguration configuration;

        public Startup(OAuthAgentConfiguration configuration) {
            this.configuration = configuration;
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseRouting();
            
            if (this.configuration.CorsEnabled)
            {
                app.UseCors();
            }

            this.ConfigureMiddleware(app);

            app.UseEndpoints(endpoints => {
                endpoints.MapControllers();
            });
        }

        public void ConfigureServices(IServiceCollection services)
        {
            if (this.configuration.CorsEnabled)
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
            }

            services.AddControllers();
            this.ConfigureDependencies(services);
        }

        private void ConfigureMiddleware(IApplicationBuilder app)
        {
            app.UseMiddleware<UnhandledExceptionMiddleware>();
        }

        public void ConfigureDependencies(IServiceCollection services)
        {
            services.AddScoped<RequestValidator>();
        }
    }
}
