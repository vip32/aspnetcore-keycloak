using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace KeyCloak.Controllers
{
    [Route("api/values")]
    public class ValuesController : Controller
    {
        [Authorize]
        //[Authorize(Roles = "admin")]
        [HttpGet]
        public async Task<IEnumerable<string>> Get()
        {
            //string accessToken = await this.HttpContext.GetTokenAsync("access_token");
            //string idToken = await this.HttpContext.GetTokenAsync("id_token");

            return new string[] { "value1", "value2" };
        }
    }

}