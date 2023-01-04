namespace IO.Curity.OAuthAgent
{
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.Extensions.DependencyInjection;
    using IO.Curity.OAuthAgent.Exceptions;

    public class Startup
    {
        private readonly OAuthAgentConfiguration configuration;

        public Startup(OAuthAgentConfiguration configuration) {
            this.configuration = configuration;
        }

        /*
         * The OAuth agent is a simple REST API
         */
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

        /*
         * CORS must be enabled if the OAuth agent is deployed to a different domain to the web origin, or disabled for same site deployments
         */
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

        /*
         * Dependencies to implement the OAuth agent are stateless so can be created as singletons
         */
        public void ConfigureDependencies(IServiceCollection services)
        {
            services.AddSingleton<LoginHandler>();
            services.AddSingleton<CookieManager>();
            services.AddSingleton<AuthorizationServerClient>();
            services.AddSingleton<IdTokenValidator>();
            services.AddSingleton<RequestValidator>();
            services.AddSingleton<ErrorLogger>();
        }
    }
}
