using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Template.Controllers;

[ApiController]
[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}")]
public partial class WeatherForecastJWTController : ControllerBase
{
    private static readonly string[] Summaries = new[]
    {
        "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
    };

    private readonly ILogger<WeatherForecastJWTController> _logger;


    public WeatherForecastJWTController(ILogger<WeatherForecastJWTController> logger)
    {
        _logger = logger;
    }

    [HttpGet]
    [MapToApiVersion("1.0")]
    [Route("[action]")]
    [Authorize]    
    public IEnumerable<WeatherForecast> EveryoneAuthenticatedWithJWTCanAccess()
    {
        return Enumerable.Range(1, 5).Select(index => new WeatherForecast
        {
            Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            TemperatureC = Random.Shared.Next(-20, 55),
            Summary = Summaries[Random.Shared.Next(Summaries.Length)]
        })
        .ToArray();
    }

    [HttpGet]
    [MapToApiVersion("1.0")]
    [Route("[action]")]
    [Authorize(AuthenticationSchemes = "Bearer")]
    [Authorize(Policy = "ManagerPolicy")]
    public IEnumerable<WeatherForecast> OnlyManagersWithJWTCanAccess()
    {
        return Enumerable.Range(1, 5).Select(index => new WeatherForecast
        {
            Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            TemperatureC = Random.Shared.Next(-20, 55),
            Summary = Summaries[Random.Shared.Next(Summaries.Length)]
        })
        .ToArray();
    }

    [HttpGet]
    [MapToApiVersion("1.0")]
    [Route("[action]")]
    [Authorize]
    [Authorize(Policy = "SupportPolicy")]
    public IEnumerable<WeatherForecast> OnlySupportWithJWTCanAccess()
    {
        return Enumerable.Range(1, 5).Select(index => new WeatherForecast
        {
            Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            TemperatureC = Random.Shared.Next(-20, 55),
            Summary = Summaries[Random.Shared.Next(Summaries.Length)]
        })
        .ToArray();
    }

    [HttpGet]
    [MapToApiVersion("1.0")]
    [Route("[action]")]
    [Authorize]
    [Authorize(Policy = "SupportPolicy")]
    [Authorize(Policy = "Pleno")]
    public IEnumerable<WeatherForecast> OnlySupportPlenoWithJWTCanAccess()
    {
        return Enumerable.Range(1, 5).Select(index => new WeatherForecast
        {
            Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            TemperatureC = Random.Shared.Next(-20, 55),
            Summary = Summaries[Random.Shared.Next(Summaries.Length)]
        })
        .ToArray();
    }

    [HttpGet]
    [MapToApiVersion("1.0")]
    [Route("[action]")]
    [Authorize]
    [Authorize(Policy = "SupportPolicy")]    
    [Authorize(Policy = "Senior")]
    public IEnumerable<WeatherForecast> OnlySupportSeniorWithJWTCanAccess()
    {
        return Enumerable.Range(1, 5).Select(index => new WeatherForecast
        {
            Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            TemperatureC = Random.Shared.Next(-20, 55),
            Summary = Summaries[Random.Shared.Next(Summaries.Length)]
        })
        .ToArray();
    }

    [HttpGet]
    [MapToApiVersion("1.0")]
    [Route("[action]")]
    [Authorize]
    [Authorize(Policy = "UserPolicy")]    
    public IEnumerable<WeatherForecast> OnlyUsersWithJWTCanAccess()
    {
        return Enumerable.Range(1, 5).Select(index => new WeatherForecast
        {
            Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            TemperatureC = Random.Shared.Next(-20, 55),
            Summary = Summaries[Random.Shared.Next(Summaries.Length)]
        })
        .ToArray();
    }

    [HttpGet]
    [MapToApiVersion("1.0")]
    [Route("[action]")]
    [Authorize(AuthenticationSchemes = "BEARER_EXTERNAL")]
    [Authorize(Policy = "UserPolicy")]    
    public IEnumerable<WeatherForecast> OnlyManagersWithExternalValidatedJwt()
    {
        return Enumerable.Range(1, 5).Select(index => new WeatherForecast
        {
            Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            TemperatureC = Random.Shared.Next(-20, 55),
            Summary = Summaries[Random.Shared.Next(Summaries.Length)]
        })
        .ToArray();
    }

}
