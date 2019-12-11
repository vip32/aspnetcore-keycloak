using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace web
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();

            // added
            services.AddRazorPages();
            services.AddServerSideBlazor();

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie()
            .AddOpenIdConnect(options =>
            {
                options.Authority = Configuration["Oidc:Authority"];
                options.ClientId = Configuration["Oidc:ClientId"];
                options.ClientSecret = Configuration["Oidc:ClientSecret"];
                options.SaveTokens = true;
                options.ResponseType = OpenIdConnectResponseType.Code; //Configuration["Oidc:ResponseType"];
                options.RequireHttpsMetadata = false; // dev only
                options.GetClaimsFromUserInfoEndpoint = true;
                options.Scope.Add("openid");
                options.Scope.Add("profile");
                options.Scope.Add("email");
                options.Scope.Add("claims");
                options.SaveTokens = true;
                //options.Events.OnTicketReceived= ctx =>
                //{
                //    // ctx contains id/access token
                //    var tokens = ctx.Properties.GetTokens().ToList();

                //    tokens.Add(new AuthenticationToken()
                //    {
                //        Name = "TicketCreated",
                //        Value = DateTime.UtcNow.ToString()
                //    });

                //    ctx.Properties.StoreTokens(tokens);

                //    return Task.CompletedTask;
                //};
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name",
                    RoleClaimType = "groups",
                    ValidateIssuer = true
                };
            });

            services.AddAuthorization();
            services.AddHttpContextAccessor();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseHttpsRedirection();

            // added
            app.UseStaticFiles();

            app.UseRouting();
            app.UseAuthentication(); // added
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();

                // added
                endpoints.MapBlazorHub();
                endpoints.MapFallbackToPage("/_Host");
            });
        }
    }
}
