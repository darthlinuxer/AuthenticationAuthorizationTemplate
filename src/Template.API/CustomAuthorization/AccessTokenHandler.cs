using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Template.API.Extensions;
using System.Security.Principal;
using System.Security.Claims;

namespace Template.API.CustomAuthorization;

 public class ValidateAccessTokenSchemeOptions : AuthenticationSchemeOptions
{ 
        public ValidateAccessTokenSchemeOptions()
        {
            
        }
    }

    public class AccessTokenHandler
        : AuthenticationHandler<ValidateAccessTokenSchemeOptions>
    {
    
        public AccessTokenHandler(
            IOptionsMonitor<ValidateAccessTokenSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock)
            : base(options, logger, encoder, clock)
        {       
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            // validation comes in here
            if (!Request.Headers.ContainsKey("Custom-Access-Token"))
            {
                return Task.FromResult(AuthenticateResult.Fail("Invalid Headers!"));
            }

            string access_token = Request.Headers["Custom-Access-Token"]!;
            //THIS IS JUST AN EXAMPLE.. DO NOT CREATE ACCESS TOKENS BY ENCODING THEM TO BASE64 !!!
            var decoded = access_token.DecodeFrom64();
            var parts = decoded.Split("%", 3, StringSplitOptions.TrimEntries);
            var ip = parts[0];
            var username = parts[1];
            var expiration = parts[2];
            //Do some expiration checks

            //Check IP Origin
            if (ip != Request.HttpContext.Connection.RemoteIpAddress.ToString()) return Task.FromResult(AuthenticateResult.Fail("Invalid IP Origin"));
            
            //If everything looks good, then create and Authentication Ticket  
            var claimsIdentity = new GenericIdentity(username);

            // generate AuthenticationTicket 
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(claimsIdentity), this.Scheme.Name);

            return Task.FromResult(AuthenticateResult.Success(ticket));
        }
    }