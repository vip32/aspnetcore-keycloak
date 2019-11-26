using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;

namespace KeyCloak.Controllers
{
    [Route("/")]
    public class HomeController : ControllerBase
    {
        [HttpGet]
        public async Task<IEnumerable<string>> Get()
        {
            return new string[]
            {
                "http://localhost:8080/auth/realms/master/.well-known/openid-configuration",
                // "http://localhost:8080/auth/realms/master/protocol/openid-connect/auth?response_type=token&client_id=naos-sample&redirect_uri=http://localhost:5000/callback",
                "http://localhost:5000/api/values",
                "http://localhost:5000/login",
                "http://localhost:5000/logout",
                HttpContext.User?.Identity?.Name,
                HttpContext.User?.Identity?.IsAuthenticated == true ? "access_token: " + await this.HttpContext.GetTokenAsync("access_token") : null, // https://www.jerriepelser.com/blog/accessing-tokens-aspnet-core-2/
                HttpContext.User?.Identity?.IsAuthenticated == true ? "id_token: " + await this.HttpContext.GetTokenAsync("id_token") : null,
            //HttpContext.Items["username"] as string
        };
        }

        [Route("login")]
        [HttpGet]
        public IActionResult Login()
        {
            if (!HttpContext.User.Identity.IsAuthenticated)
            {
                return Challenge(OpenIdConnectDefaults.AuthenticationScheme);
            }

            return new ObjectResult(HttpContext.User.Identity);
        }

        [Route("logout")]
        [HttpGet]
        public IActionResult Logout()
        {
            return new SignOutResult(new[]
            {
                OpenIdConnectDefaults.AuthenticationScheme,
                CookieAuthenticationDefaults.AuthenticationScheme
            });
        }
    }
}