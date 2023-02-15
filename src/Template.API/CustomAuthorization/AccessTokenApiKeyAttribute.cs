using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Template.API.CustomAuthorization;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class AccessTokenApiKeyAttribute : Attribute, IAuthorizationFilter
{
    private const string ApiHeaderName = "X-API-KEY";
    public void OnAuthorization(AuthorizationFilterContext context)
    {
        string? apiKey = context.HttpContext.Request.Headers[ApiHeaderName];
        if(string.IsNullOrWhiteSpace(apiKey) || apiKey != "123") 
        {
            context.Result = new UnauthorizedResult();
        }                
    }
}