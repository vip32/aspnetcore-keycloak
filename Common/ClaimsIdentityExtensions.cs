namespace Common
{
    using System;
    using System.IdentityModel.Tokens.Jwt;
    using System.Security.Claims;

    public static partial class Extensions
    {
        /// <summary>
        /// Gets an identity claim
        /// </summary>
        /// <returns></returns>
        public static Claim GetClaim(this ClaimsIdentity source, string type)
        {
            if (source == null || string.IsNullOrEmpty(type))
            {
                return default;
            }

            var claim = source.FindFirst(type);
            if (claim != null)
            {
                return claim;
            }

            return default;
        }

        /// <summary>
        /// Adds or updates a identity claim
        /// </summary>
        /// <returns></returns>
        public static string GetClaimValue(this ClaimsIdentity source, string type)
        {
            if (source == null || string.IsNullOrEmpty(type))
            {
                return default;
            }

            var claim = source.FindFirst(type);
            if (claim != null)
            {
                return claim.Value;
            }

            return default;
        }

        /// <summary>
        /// Adds or updates a identity claim
        /// </summary>
        /// <returns></returns>
        public static ClaimsIdentity SetClaim(this ClaimsIdentity source, Claim claim)
        {
            if (source == null || claim == null)
            {
                return source;
            }

            if (source.FindFirst(claim.Type) != null)
            {
                source.RemoveClaim(claim);
            }

            source.AddClaim(claim);
            return source;
        }

        /// <summary>
        /// Adds or updates a identity claim
        /// </summary>
        /// <returns></returns>
        public static ClaimsIdentity SetClaimValue(this ClaimsIdentity source, string type, string value)
        {
            if (source == null || string.IsNullOrEmpty(type))
            {
                return source;
            }

            var claim = source.FindFirst(type);
            if (claim != null)
            {
                source.RemoveClaim(claim);
            }

            source.AddClaim(new Claim(type, value));
            return source;
        }

        /// <summary>
        /// Adds or updates a identity claim
        /// </summary>
        /// <returns></returns>
        public static ClaimsIdentity AddOrUpdateClaim(this ClaimsIdentity source, string type, long value)
        {
            if (source == null || string.IsNullOrEmpty(type))
            {
                return source;
            }

            var claim = source.FindFirst(type);
            if (claim != null)
            {
                source.RemoveClaim(claim);
            }

            source.AddClaim(new Claim(type, value.ToString()));
            return source;
        }

        /// <summary>
        /// Adds or updates a identity claim
        /// </summary>
        /// <returns></returns>
        public static ClaimsIdentity AddOrUpdateClaim(this ClaimsIdentity source, string type, long? value)
        {
            if (source == null || string.IsNullOrEmpty(type))
            {
                return source;
            }

            var claim = source.FindFirst(type);
            if (claim != null)
            {
                source.RemoveClaim(claim);
            }

            source.AddClaim(new Claim(type, value?.ToString()));
            return source;
        }

        public static ClaimsIdentity SetIdentityClaims(this ClaimsIdentity source, string accessToken, string refreshToken)
        {
            return source
                .SetClaimValue(ClaimType.AccessToken, accessToken)
                .SetClaimValue(ClaimType.RefreshToken, refreshToken)
                .SetClaimValue(ClaimType.AccessTokenExpires, ((DateTimeOffset)new JwtSecurityToken(accessToken).ValidTo).ToUnixTimeSeconds().ToString())
                .SetClaimValue(ClaimType.RefreshTokenExpires, ((DateTimeOffset)new JwtSecurityToken(refreshToken).ValidTo).ToUnixTimeSeconds().ToString());
        }
    }
}
