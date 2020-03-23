using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;

namespace KeyCloak.Controllers
{
    [Route("/")]
    public class HomeController : ControllerBase
    {
        private readonly IConfiguration configuration;

        public HomeController(IConfiguration configuration)
        {
            this.configuration = configuration;
        }

        [HttpGet]
        public async Task<IEnumerable<string>> Get()
        {
            return new string[]
            {
                $"{this.configuration["Oidc:Authority"]}/.well-known/openid-configuration",
                $"{HttpContext.Request.Scheme}://{HttpContext.Request.Host}/api/values",
                $"{HttpContext.Request.Scheme}://{HttpContext.Request.Host}/signin-oidc",
                $"{HttpContext.Request.Scheme}://{HttpContext.Request.Host}/signout-oidc",
                "==== IDENTITY ===============",
                HttpContext.User?.Identity?.Name,
                //"==== CLAIMS ===============",
                HttpContext.User?.Claims?.Any() == true ? HttpContext.User?.Claims?.Select(h => $"CLAIM {h.Type}: {h.Value}").Aggregate((i, j) => i + " | " + j) : null,
                "==== TOKENS ===============",
                HttpContext.User?.Identity?.IsAuthenticated == true ? "access_token: " + await this.HttpContext.GetTokenAsync("access_token") : null, // https://www.jerriepelser.com/blog/accessing-tokens-aspnet-core-2/
                HttpContext.User?.Identity?.IsAuthenticated == true ? "id_token: " + await this.HttpContext.GetTokenAsync("id_token") : null,
                HttpContext.User?.Identity?.IsAuthenticated == true ? "refresh_token: " + await this.HttpContext.GetTokenAsync("refresh_token") : null,
                "==== HEADERS ===============",
                HttpContext.Request.Headers.Select(h => $"HEADER {h.Key}: {h.Value}").Aggregate((i, j) => i + " | " + j)
                //HttpContext.Items["username"] as string
            };
        }
    }
}