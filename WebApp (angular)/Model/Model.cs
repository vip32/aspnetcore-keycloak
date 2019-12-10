using System.Collections.Generic;

namespace WebApp__angular_
{
    public class OIDCConfig
    {
        public OIDCConfig() { _additionalLoginParameters = new Dictionary<string, string>(); }

        public string stsServer { get; set; }
        public string redirect_url { get; set; }
        public string client_id { get; set; }
        public string response_type { get; set; }
        public string scope { get; set; }
        public string post_logout_redirect_uri { get; set; }
        public string post_login_route { get; set; }
        public bool start_checksession { get; set; }
        public bool silent_renew { get; set; }
        public string silent_renew_url { get; set; }
        public string startup_route { get; set; }
        public string forbidden_route { get; set; }
        public string unauthorized_route { get; set; }
        public bool auto_userinfo { get; set; }
        public bool log_console_warning_active { get; set; }
        public bool log_console_debug_active { get; set; }
        public int max_id_token_iat_offset_allowed_in_seconds { get; set; }

        private Dictionary<string, string> _additionalLoginParameters;
        public Dictionary<string, string> additional_login_parameters { get { return _additionalLoginParameters; } }
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