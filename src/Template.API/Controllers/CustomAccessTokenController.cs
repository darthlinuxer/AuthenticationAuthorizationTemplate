using Template.API.CustomAuthorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Template.Controllers;

[ApiController]
[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}")]
public class CustomAccessTokenController : ControllerBase
{
    private readonly ILogger<CustomAccessTokenController> _logger;


    public CustomAccessTokenController(ILogger<CustomAccessTokenController> logger)
    {
        _logger = logger;
    }    

    [HttpGet]
    [Route("[action]")]
    [MapToApiVersion("1.0")]
    [Authorize(AuthenticationSchemes = "Custom-Access-Token-Scheme")]
    public IActionResult WhoAmIFromToken()
    {
        return Ok(User.Identity.Name);
    }

    [HttpGet]
    [Route("[action]")]
    [MapToApiVersion("1.0")]
    [AccessTokenApiKey]
    public IActionResult CustomAuthorizationThroughAttribute()
    {
        return Ok("You are authenticated!");
    }

}
