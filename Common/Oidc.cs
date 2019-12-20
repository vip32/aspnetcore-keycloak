using IdentityModel.Client;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;

namespace Common
{
    public static class Oidc
    {
        private static OidcWellKnown WellKnownConfiguration { get; set; }

        private static JwtKs JwtKs { get; set; }

        public static async Task<OidcWellKnown> GetWellKnownConfigurationAsync(string authority)
        {
            if (WellKnownConfiguration == null)
            {
                var client = new HttpClient
                {
                    BaseAddress = new Uri(authority.TrimEnd('/') + "/")
                };
                client.DefaultRequestHeaders.Clear();
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                var response = await client.GetAsync(".well-known/openid-configuration").ConfigureAwait(false);
                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    WellKnownConfiguration = JsonConvert.DeserializeObject<OidcWellKnown>(content);
                }
            }

            return WellKnownConfiguration;
        }

        public static async Task<JwtKs> GetJwtKs(string authority)
        {
            if (JwtKs == null)
            {
                var configuration = await GetWellKnownConfigurationAsync(authority).ConfigureAwait(false);
                var client = new HttpClient
                {
                    BaseAddress = new Uri(configuration.jwks_uri)
                };
                client.DefaultRequestHeaders.Clear();
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                var response = await client.GetAsync("").ConfigureAwait(false);
                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    JwtKs = JsonConvert.DeserializeObject<JwtKs>(content);
                }
            }

            return JwtKs;
        }

        public static async Task<IIdentity> UpdateTokenClaims(ClaimsIdentity identity, string authority, string clientId, string clientSecret, bool force = false)
        {
            // always refresh the token, needs refresh token to be present in identity claims
            // or let a timer doe this constantly? https://github.com/aspnet/AspNetCore/issues/16241
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var exp = long.Parse(identity.GetClaimValue(ClaimType.AccessTokenExpires));
            Console.WriteLine($"++++++ TOKEN now: {now}, exp: {exp} ++++++++");

            if (now >= exp || force)
            {
                // tokens expired https://identitymodel.readthedocs.io/en/latest/client/token.html#requesting-a-token-using-the-refresh-token-grant-type
                Console.WriteLine("++++++ TOKEN expired ++++++++");
                var response = await new HttpClient().RequestRefreshTokenAsync(new RefreshTokenRequest
                {
                    Address = (await GetWellKnownConfigurationAsync(authority).ConfigureAwait(false)).token_endpoint,
                    ClientId = clientId,
                    ClientSecret = clientSecret,
                    RefreshToken = identity.GetClaimValue(ClaimType.RefreshToken)
                }).ConfigureAwait(false);

                if (!response.IsError)
                {
                    Console.WriteLine($"++++++ TOKEN refreshed {response.AccessToken} ++++++++");
                    identity.SetIdentityClaims(response.AccessToken, response.RefreshToken);
                }
            }
            else
            {
                Console.WriteLine($"++++++ TOKEN expires at {exp} in {TimeSpan.FromSeconds(exp - now).Minutes} minutes ++++++++");
            }

            return identity;
        }
    }


    public class OidcWellKnown
    {
        public string authorization_endpoint { get; set; }
        public string token_endpoint { get; set; }
        public List<string> token_endpoint_auth_methods_supported { get; set; }
        public string jwks_uri { get; set; }
        public List<string> response_modes_supported { get; set; }
        public List<string> subject_types_supported { get; set; }
        public List<string> id_token_signing_alg_values_supported { get; set; }
        public bool http_logout_supported { get; set; }
        public bool frontchannel_logout_supported { get; set; }
        public string end_session_endpoint { get; set; }
        public List<string> response_types_supported { get; set; }
        public List<string> scopes_supported { get; set; }
        public string issuer { get; set; }
        public List<string> claims_supported { get; set; }
        public bool request_uri_parameter_supported { get; set; }
        public string tenant_region_scope { get; set; }
        public string cloud_instance_name { get; set; }
        public string cloud_graph_host_name { get; set; }
        public string msgraph_host { get; set; }
        public string rbac_url { get; set; }
    }

    public class JwtKey
    {
        public string kty { get; set; }
        public string use { get; set; }
        public string kid { get; set; }
        public string x5t { get; set; }
        public string n { get; set; }
        public string e { get; set; }
        public List<string> x5c { get; set; }
        public string issuer { get; set; }
    }

    public class JwtKs
    {
        public List<JwtKey> keys { get; set; }
    }
}
