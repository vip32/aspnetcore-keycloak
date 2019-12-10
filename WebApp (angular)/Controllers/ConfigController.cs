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
    [Route("api/[controller]")]
    public class ConfigController : Controller
    {

        private IConfiguration _configuration;
        private IWebHostEnvironment _env;

        private OidcWellKnown _wellKnown;
        private JwtKs _jwtKs;

        public ConfigController(IConfiguration config, IWebHostEnvironment env)
        {
            _configuration = config;
            _env = env;
        }

        private async Task<OidcWellKnown> GetWellKnownAsync()
        {
            if (_wellKnown == null)
            {
                var client = new HttpClient();
                client.BaseAddress = new Uri(_configuration["Oidc:Authority"] + "/");
                client.DefaultRequestHeaders.Clear();
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                HttpResponseMessage response = await client.GetAsync(".well-known/openid-configuration");
                if (response.IsSuccessStatusCode)
                {
                    var wellknownString = await response.Content.ReadAsStringAsync();
                    _wellKnown = JsonConvert.DeserializeObject<OidcWellKnown>(wellknownString);
                }
            }
            return _wellKnown;
        }

        private async Task<JwtKs> GetJwtKs()
        {
            if (_jwtKs == null)
            {
                var client = new HttpClient();
                var wellKnown = await GetWellKnownAsync();
                client.BaseAddress = new Uri(wellKnown.jwks_uri);
                client.DefaultRequestHeaders.Clear();
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                HttpResponseMessage response = await client.GetAsync("");
                if (response.IsSuccessStatusCode)
                {
                    var jwrkstring = await response.Content.ReadAsStringAsync();
                    _jwtKs = JsonConvert.DeserializeObject<JwtKs>(jwrkstring);
                }
            }

            return _jwtKs;
        }


        [HttpGet(".well-known/openid-configuration")]
        public async Task<OidcWellKnown> WellKnownAsync()
        {
            string protocol = Request.IsHttps ? "https://" : "http://";
            string jwks_uri = $"{protocol}{Request.Host.ToUriComponent()}/api/config/discovery/keys";
            var wellKnown = await GetWellKnownAsync();
            wellKnown.jwks_uri = jwks_uri;
            return wellKnown;
        }

        [HttpGet("discovery/keys")]
        public async Task<JwtKs> KeysAsync()
        {
            return await GetJwtKs();
        }

        [HttpGet("configuration")]
        public async Task<OIDCConfig> ConfigurationAsync()
        {
            OIDCConfig config = new OIDCConfig();
            OidcWellKnown wellKnown = await GetWellKnownAsync();

            string protocol = Request.IsHttps ? "https://" : "http://";
            config.stsServer = $"{protocol}{Request.Host.ToUriComponent()}/api/config";
            config.redirect_url = $"{protocol}{Request.Host.ToUriComponent()}/";
            config.client_id = _configuration["Oidc:ClientId"];
            config.response_type = "id_token token";
            if (!String.IsNullOrEmpty(_configuration["Oidc:Scope"]))
            {
                config.scope = _configuration["Oidc:Scope"];
            }
            else
            {
                config.scope = "openid profile email"; // https://graph.microsoft.com/User.Read
            }
            config.post_logout_redirect_uri = $"{protocol}{Request.Host.ToUriComponent()}/";
            config.post_login_route = "/home";
            config.forbidden_route = "/home";
            config.unauthorized_route = "/home";
            config.auto_userinfo = false;
            config.log_console_warning_active = true;
            config.log_console_debug_active = _env.IsDevelopment();
            config.max_id_token_iat_offset_allowed_in_seconds = 1000;
            if (!String.IsNullOrEmpty(_configuration["Oidc:Resource"]))
            {
                config.additional_login_parameters["resource"] = _configuration["Oidc:Resource"];
            }
            if (!String.IsNullOrEmpty(_configuration["Oidc:Prompt"]))
            {
                config.additional_login_parameters["prompt"] = _configuration["Oidc:Prompt"];
            }
            return config;
        }
    }
}