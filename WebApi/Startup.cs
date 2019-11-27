using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace KeyCloak3
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
            services.AddControllers()
                .AddNewtonsoftJson(x => x.SerializerSettings.ReferenceLoopHandling = Newtonsoft.Json.ReferenceLoopHandling.Ignore);

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie()
            .AddOpenIdConnect(options =>
            {
                options.Authority = Configuration["Oidc:Authority"];
                //options.MetadataAddress
                //options.SignedOutRedirectUri = "/";
                options.ClientId = Configuration["Oidc:ClientId"];
                options.ClientSecret = Configuration["Oidc:ClientSecret"];
                options.SaveTokens = true;
                options.GetClaimsFromUserInfoEndpoint = true;
                options.ResponseType = OpenIdConnectResponseType.Code; //Configuration["Oidc:ResponseType"];
                options.RequireHttpsMetadata = false; // dev only
                options.GetClaimsFromUserInfoEndpoint = true;
                options.Scope.Add("email");
                options.Scope.Add("openid");
                options.Scope.Add("claims");
                options.Scope.Add("profile");
                options.SaveTokens = true;
                //options.Events = new OpenIdConnectEvents
                //{
                //    OnTokenResponseReceived = async ctx =>
                //    {
                //        var a = ctx.Principal;
                //    },
                //    OnAuthorizationCodeReceived = async ctx =>
                //    {
                //        var a = ctx.Principal;
                //    }
                //};

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name",
                    RoleClaimType = "groups",
                    ValidateIssuer = true
                };
            });

            // access token: http://localhost:8080/auth/realms/master/protocol/openid-connect/auth?response_type=token&client_id=naos-sample&redirect_uri=https://localhost:5001/signin-oidc

            services.AddAuthorization();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseStaticFiles();
            app.UseHttpsRedirection();
            app.UseRouting();
            app.UseAuthentication(); // added
            app.UseAuthorization();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
