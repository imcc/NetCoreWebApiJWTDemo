using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using JWTDemoForNetCore.Models.Account;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;

namespace JWTDemoForNetCore.Controllers
{
    [Route("/token")]
    public class TokenController : Controller
    {
        private readonly JwtIssuerOptions _jwtOptions;
        private readonly ILogger _logger;
        private readonly JsonSerializerSettings _serializerSettings;

        public TokenController(IOptions<JwtIssuerOptions> jwtOptions, ILoggerFactory loggerFactory)
        {
            _jwtOptions = jwtOptions.Value;
            ThrowIfInvalidOptions(_jwtOptions);

            _logger = loggerFactory.CreateLogger<TokenController>();

            _serializerSettings = new JsonSerializerSettings
            {
                Formatting = Formatting.Indented
            };
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<ActionResult> Post(LoginViewModel view)
        {
            var identity = await GetClaimsIdentity(view);
            if (identity == null)
            {
                _logger.LogInformation($"Invalid username ({view?.Username}) or password.");
                return BadRequest("Invalid credentials");
            }

            var claims = new List<Claim>
            {
                //new Claim(JwtRegisteredClaimNames.Sub, identity.Claims.FirstOrDefault(x => x.Type==ClaimTypes.NameIdentifier)?.Value),
                new Claim(JwtRegisteredClaimNames.Jti, await _jwtOptions.JtiGenerator()),
                new Claim(JwtRegisteredClaimNames.Iat, ToUnixEpochDate(_jwtOptions.IssuedAt).ToString(),
                    ClaimValueTypes.Integer64)
            };

            //claims.AddRange(identity.Claims.Where(x => x.Type != ClaimsIdentity.DefaultNameClaimType));
            claims.AddRange(identity.Claims);

            ReplaceClaimKey(claims);

            var jwt = new JwtSecurityToken(
                _jwtOptions.Issuer,
                _jwtOptions.Audience,
                claims,
                _jwtOptions.NotBefore,
                _jwtOptions.Expiration,
                _jwtOptions.SigningCredentials
            );

            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

            var response = new
            {
                access_token = encodedJwt,
                expires_in = (int)_jwtOptions.ValidFor.TotalSeconds
            };

            var json = JsonConvert.SerializeObject(response, _serializerSettings);
            return new OkObjectResult(json);
        }

        private static Task<ClaimsIdentity> GetClaimsIdentity(LoginViewModel user)
        {
            //跳过验证
            var loginSuccess = !string.IsNullOrWhiteSpace(user?.Username);

            if (loginSuccess)
            {
                var claims = new List<Claim>();
                //用户id
                claims.Add(new Claim(ClaimTypes.NameIdentifier, "1"));
                claims.Add(new Claim(ClaimTypes.Role, "Test"));

                if (user.Username.ToLower() == "mingchen")
                {
                    claims.Add(new Claim(ClaimTypes.Role, "Admin"));
                }

                return Task.FromResult(new ClaimsIdentity(new GenericIdentity(user.Username, "Token"), claims));
            }

            // Credentials are invalid, or account doesn't exist
            return Task.FromResult<ClaimsIdentity>(null);
        }

        private static void ThrowIfInvalidOptions(JwtIssuerOptions options)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));

            if (options.ValidFor <= TimeSpan.Zero)
                throw new ArgumentException("Must be a non-zero TimeSpan.", nameof(JwtIssuerOptions.ValidFor));

            if (options.SigningCredentials == null)
                throw new ArgumentNullException(nameof(JwtIssuerOptions.SigningCredentials));

            if (options.JtiGenerator == null)
                throw new ArgumentNullException(nameof(JwtIssuerOptions.JtiGenerator));
        }

        /// <returns>Date converted to seconds since Unix epoch (Jan 1, 1970, midnight UTC).</returns>
        private static long ToUnixEpochDate(DateTime date)
        {
            return (long)Math.Round((date.ToUniversalTime() - new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero))
                .TotalSeconds);
        }

        private static void ReplaceClaimKey(List<Claim> claims)
        {
            Action<string, string> replaceValue = (originName, newName) =>
             {
                 if (claims.Any(x => x.Type == originName))
                 {
                     var origins = claims.Where(x => x.Type == originName).ToList();
                     if (claims.Any(x => x.Type == newName))
                     {
                         claims.RemoveAll(x => x.Type == newName);
                     }

                     foreach (var item in origins)
                     {
                         claims.Remove(item);

                         claims.Add(new Claim(newName, item.Value));
                     }
                 }
             };

            replaceValue(ClaimTypes.NameIdentifier, JwtRegisteredClaimNames.Sub);
            replaceValue(ClaimTypes.Name, JwtRegisteredClaimNames.UniqueName);
            replaceValue(ClaimTypes.Role, "role");
        }
    }
}