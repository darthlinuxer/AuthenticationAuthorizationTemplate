using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using Template.API.Extensions;
using AAA.API.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace pos2_aaa_template.Controllers
{
    [ApiController]
    [ApiVersion("1.0")]
    [Route("api/v{version:apiVersion}")]
    public class AccessControl : ControllerBase
    {

        private List<UserRecordDTO> registeredUsers = new()
        {
            new(){UserName="manager", Password="123",Role="manager",Audience="company1",SecurityLevel="100"},
            new(){UserName="supportJunior", Password="123",Role="support",Audience="company2",SecurityLevel="20"},
            new(){UserName="supportPleno", Password="123",Role="support",Audience="company1",SecurityLevel="51"},
            new(){UserName="supportSenior", Password="123",Role="support",Audience="company1",SecurityLevel="92"},
            new(){UserName="othersupportSenior", Password="123",Role="support",Audience="company3", SecurityLevel="99"},
            new(){UserName="dev", Password="123",Role="user",Audience="company1"}
        };
        private readonly ILogger<AccessControl> _logger;


        public AccessControl(ILogger<AccessControl> logger)
        {
            _logger = logger;
        }


        [HttpGet]
        [Route("[action]")]
        [ApiExplorerSettings(IgnoreApi = true)]
        public IActionResult AccessDenied() => Unauthorized();

        [HttpGet]
        [Route("[action]")]
        [ApiExplorerSettings(IgnoreApi = true)]
        public IActionResult LoginError() => BadRequest("You must Login first!");

        [HttpPost]
        [Route("[action]")]
        [MapToApiVersion("1.0")]
        public IActionResult LoginAndReturnCookieAsync([FromBody] UserRecordDTO user)
        {
            var existingUser = registeredUsers
                    .FirstOrDefault(
                        c => c.UserName == user.UserName && c.Password == user.Password);

            //AUTHENTICATION
            if (existingUser is null) return BadRequest("User or Password is Invalid!");

            //REBUILDING USER IDENTITY WITH HIS CLAIMS FROM DB
            List<Claim>? _claims = new() {
                    new Claim(ClaimTypes.Role,existingUser.Role),
                    new Claim("SecurityLevel", existingUser.SecurityLevel)
              };

            GenericIdentity? genericIdentity = new(user.UserName, CookieAuthenticationDefaults.AuthenticationScheme);
            var userIdentity = new ClaimsIdentity(genericIdentity, _claims);


            var authProperties = new AuthenticationProperties
            {
                AllowRefresh = true,
                ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(10),
                IsPersistent = true,
                IssuedUtc = DateTime.Now,
            };

            HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(userIdentity),
                authProperties).GetAwaiter().GetResult();

            return Ok(new { msg = "User Logged and Cookie generated! Check your Browser!" });
        }

        [HttpGet]
        [Route("[action]")]
        [MapToApiVersion("1.0")]
        public IActionResult LogoutCookie()
        {
            HttpContext.SignOutAsync(
            CookieAuthenticationDefaults.AuthenticationScheme).GetAwaiter().GetResult();
            return Ok(new { msg = "User Logged Out and Cookie Removed! Check your Browser!" });
        }


        [HttpPost]
        [Route("[action]")]
        [MapToApiVersion("1.0")]
        public IActionResult LoginAndReturnJWT([FromBody] UserRecordDTO user)
        {
            var existingUser = registeredUsers
                    .FirstOrDefault(
                        c => c.UserName == user.UserName && c.Password == user.Password);

            //AUTHENTICATION
            if (existingUser is null) return BadRequest("User or Password is Invalid!");

            //REBUILDING USER IDENTITY WITH HIS CLAIMS FROM DB
            var _claims = new List<Claim>(){
                    new Claim(ClaimTypes.Role,existingUser.Role ?? "user"),
                    new Claim("SecurityLevel", existingUser.SecurityLevel)
              };
            var genericIdentity = new GenericIdentity(user.UserName);
            var userIdentity = new ClaimsIdentity(genericIdentity, _claims);

            //BUILDING JWT TOKEN
            var tokenHandler = new JwtSecurityTokenHandler();
            var _tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = userIdentity,
                Expires = DateTime.UtcNow.AddMinutes(5),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(Encoding.UTF8.GetBytes("very_long_and_secret_rdi_password")),
                    SecurityAlgorithms.HmacSha256Signature),
                Issuer = "aaa",
                Audience = existingUser.Audience,
                IssuedAt = DateTime.UtcNow,
                NotBefore = DateTime.UtcNow
            };
            var token = tokenHandler.CreateToken(_tokenDescriptor);
            return Ok(tokenHandler.WriteToken(token));
        }

        [HttpPost]
        [Route("[action]")]
        [MapToApiVersion("1.0")]
        [Authorize]
        public IActionResult LoginAndReturnCustomAccessToken()
        {
            var ip = Request.HttpContext.Connection.RemoteIpAddress.ToString();
            var username = User.Identity.Name;
            var expiration = DateTime.Now.AddDays(1).ToShortDateString();
            var seed = string.Join("%",ip,username,expiration);
            var encodedAccessToken = seed.EncodeTo64();
            return Ok(new {custom_access_token = encodedAccessToken});      
        }
    }
}
