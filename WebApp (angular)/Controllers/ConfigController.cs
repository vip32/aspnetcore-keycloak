using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System.Net.Http;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Hosting;
using Newtonsoft.Json;
using Microsoft.Extensions.Hosting;

namespace WebApp__angular_.Controllers
{
    [Route("api/config")]
    public class ConfigController : Controller
    {
        private readonly IConfiguration configuration;
        private readonly IWebHostEnvironment environment;

        private OidcWellKnown wellKnown;
        private JwtKs _jwtKs;

        public ConfigController(IConfiguration config, IWebHostEnvironment environment)
        {
            this.configuration = config;
            this.environment = environment;
        }

        [HttpGet(".well-known/openid-configuration")]
        public async Task<OidcWellKnown> WellKnownAsync()
        {
            var protocol = this.Request.IsHttps ? "https://" : "http://";
            var jwks_uri = $"{protocol}{this.Request.Host.ToUriComponent()}/api/config/discovery/keys";
            var wellKnown = await this.GetWellKnownAsync().ConfigureAwait(false);
            wellKnown.jwks_uri = jwks_uri;
            return wellKnown;
        }

        [HttpGet("discovery/keys")]
        public async Task<JwtKs> KeysAsync()
        {
            return await this.GetJwtKs().ConfigureAwait(false);
        }

        [HttpGet("configuration")]
        public async Task<OidcConfig> ConfigurationAsync()
        {
            var config = new OidcConfig();
            var wellKnown = await this.GetWellKnownAsync().ConfigureAwait(false);

            var protocol = this.Request.IsHttps ? "https://" : "http://";
            config.stsServer = $"{protocol}{this.Request.Host.ToUriComponent()}/api/config";
            config.redirect_url = $"{protocol}{this.Request.Host.ToUriComponent()}/";
            config.client_id = this.configuration["Oidc:ClientId"];
            config.response_type = "id_token token";
            if (!String.IsNullOrEmpty(this.configuration["Oidc:Scope"]))
            {
                config.scope = this.configuration["Oidc:Scope"];
            }
            else
            {
                config.scope = "openid profile email"; // https://graph.microsoft.com/User.Read
            }
            config.post_logout_redirect_uri = $"{protocol}{this.Request.Host.ToUriComponent()}/";
            config.post_login_route = "/home";
            config.forbidden_route = "/home";
            config.unauthorized_route = "/home";
            config.auto_userinfo = false;
            config.log_console_warning_active = true;
            config.log_console_debug_active = this.environment.IsDevelopment();
            config.max_id_token_iat_offset_allowed_in_seconds = 1000;
            if (!String.IsNullOrEmpty(this.configuration["Oidc:Resource"]))
            {
                config.additional_login_parameters["resource"] = this.configuration["Oidc:Resource"];
            }
            if (!String.IsNullOrEmpty(this.configuration["Oidc:Prompt"]))
            {
                config.additional_login_parameters["prompt"] = this.configuration["Oidc:Prompt"];
            }
            return config;
        }

        private async Task<OidcWellKnown> GetWellKnownAsync()
        {
            if (this.wellKnown == null)
            {
                var client = new HttpClient();
                client.BaseAddress = new Uri(this.configuration["Oidc:Authority"] + "/");
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                var response = await client.GetAsync(".well-known/openid-configuration").ConfigureAwait(false);
                if (response.IsSuccessStatusCode)
                {
                    var wellknownString = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    this.wellKnown = JsonConvert.DeserializeObject<OidcWellKnown>(wellknownString);
                }
            }
            return this.wellKnown;
        }

        private async Task<JwtKs> GetJwtKs()
        {
            if (this._jwtKs == null)
            {
                var client = new HttpClient();
                var wellKnown = await this.GetWellKnownAsync().ConfigureAwait(false);
                client.BaseAddress = new Uri(wellKnown.jwks_uri);
                client.DefaultRequestHeaders.Clear();
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                var response = await client.GetAsync("").ConfigureAwait(false);
                if (response.IsSuccessStatusCode)
                {
                    var jwrkstring = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    this._jwtKs = JsonConvert.DeserializeObject<JwtKs>(jwrkstring);
                }
            }

            return this._jwtKs;
        }
    }
}