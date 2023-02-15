using System.Net;
using System.Security.Claims;
using System.Text;
using Template.API.CustomAuthorization;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Versioning;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;
using Swashbuckle.AspNetCore.SwaggerUI;

var builder = WebApplication.CreateBuilder(args);

var _configuration = builder.Configuration;
var _env = builder.Environment;

builder.Services.AddRouting(options => options.LowercaseUrls = true);

builder.Services.AddApiVersioning(options =>
{
    options.DefaultApiVersion = new ApiVersion(1, 0);
    options.ReportApiVersions = true;
    options.AssumeDefaultVersionWhenUnspecified = true;
    options.ApiVersionReader = new UrlSegmentApiVersionReader();
});

builder.Services.AddVersionedApiExplorer(options =>
{
    options.GroupNameFormat = "'v'VVV";
    options.SubstituteApiVersionInUrl = true;
});

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(ConfigureSwaggerGen);

builder.Services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                })
                  .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, config =>
                {
                    config.Cookie.Name = "AAA.Cookie";
                    config.Cookie.HttpOnly = true;
                    //Quando um cookie é marcado como HTTPOnly, isso significa que ele não pode ser acessado 
                    //por scripts de página, como JavaScript. Isso ajuda a prevenir ataques (XSS).
                    //Ao definir config.Cookie.HttpOnly no código, você está configurando a aplicação para 
                    //enviar cookies HTTPOnly para o navegador. Isso significa que o cookie só pode ser 
                    //acessado pelo servidor, e não pode ser acessado ou manipulado pelo cliente.                    
                    config.AccessDeniedPath = "/api/v1/accessdenied";
                    config.LoginPath = "/api/v1/loginerror";
                    config.SlidingExpiration = true;
                    config.ExpireTimeSpan = TimeSpan.FromMinutes(5);
                    config.Cookie.MaxAge = TimeSpan.FromDays(30);
                    config.ClaimsIssuer = "issuer1";
                    config.Events = new CookieAuthenticationEvents
                    {
                        OnSignedIn = context =>
                        {
                            return Task.CompletedTask;
                        },
                        OnValidatePrincipal = context =>
                        {
                            return Task.CompletedTask;
                        }
                    };
                })
                .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
                {
                    options.RequireHttpsMetadata = false;
                    options.SaveToken = true;
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidIssuer = "issuer1",
                        ValidateIssuer = true,
                        RequireAudience = true,
                        ValidAudiences = new List<string>()
                        {
                              "company1","company2"
                         },
                        ValidateAudience = true,
                        RequireSignedTokens = true,
                        IssuerSigningKey =
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes("very_long_and_secret_unkown_password")),
                        ValidateIssuerSigningKey = true,
                        RequireExpirationTime = true,
                        ValidateLifetime = true,
                        ClockSkew = TimeSpan.Zero
                    };
                    options.Events = new JwtBearerEvents()
                    {
                        OnChallenge = context =>
                        {
                            context.HandleResponse();
                            context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                            context.Response.WriteAsJsonAsync(new
                            {
                                error = context.Error,
                                description = context.ErrorDescription
                            });
                            return Task.CompletedTask;
                        },
                        OnTokenValidated = context =>
                        {
                            context.HttpContext.User = context.Principal;
                            return Task.CompletedTask;
                        },
                        OnMessageReceived = context =>
                        {
                            return Task.CompletedTask;
                        },
                        OnAuthenticationFailed = context =>
                        {
                            return Task.CompletedTask;
                        },
                        OnForbidden = context =>
                        {
                            return Task.CompletedTask;
                        }
                    };
                })
                .AddJwtBearer("BEARER_EXTERNAL", options =>
                {
                    var validAudiences = new List<string>();
                    _configuration.GetSection("Authentication:ValidAudiences").Bind(validAudiences);
                    options.Authority = _configuration["Authentication:Url"];
                    options.RequireHttpsMetadata = _configuration.GetValue<bool>("Authentication:RequireHttpsMetadata");
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateAudience = false,
                        ValidAudiences = validAudiences
                    };
                    options.Events = new JwtBearerEvents()
                    {
                        OnChallenge = (context) =>
                        {
                            context.HandleResponse();
                            context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                            context.Response.WriteAsJsonAsync(new
                            {
                                error = context.Error,
                                description = context.ErrorDescription
                            });
                            return Task.CompletedTask;
                        },
                        OnTokenValidated = (context) =>
                        {
                            return Task.CompletedTask;
                        }

                    };
                })
                .AddScheme<ValidateAccessTokenSchemeOptions, AccessTokenHandler>
                ("Custom-Access-Token-Scheme", op =>
                {

                });


builder.Services.AddAuthorization(config =>
{
    config.AddPolicy("ManagerPolicy", policyBuilder =>
    {
        policyBuilder.RequireAuthenticatedUser();
        policyBuilder.RequireClaim(claimType: ClaimTypes.Role, new[] { "manager", "MANAGER" });
    });
    config.AddPolicy("SupportPolicy", policyBuilder =>
    {
        policyBuilder.RequireAuthenticatedUser();
        policyBuilder.RequireClaim(claimType: ClaimTypes.Role, new[] { "manager", "support", "MANAGER", "SUPPORT" });
    });
    config.AddPolicy("UserPolicy", policyBuilder =>
    {
        policyBuilder.RequireAuthenticatedUser();
        policyBuilder.RequireClaim(claimType: ClaimTypes.Role, new[] { "manager", "support", "user", "MANAGER", "SUPPORT", "USER" });
    });

    config.AddPolicy("Senior", policyBuilder =>
    {
        policyBuilder.RequireAuthenticatedUser();
        policyBuilder.RequireAssertion((context) =>
        {
            var claim = context.User.Claims.FirstOrDefault(c => c.Type == "SecurityLevel");
            if (claim is null) return false;
            if (Int32.Parse(claim.Value) >= 90) return true;
            return false;
        });
    });

    config.AddPolicy("Pleno", policyBuilder =>
    {
        policyBuilder.RequireAuthenticatedUser();
        policyBuilder.RequireAssertion((context) =>
        {
            var claim = context.User.Claims.FirstOrDefault(c => c.Type == "SecurityLevel");
            if (claim is null) return false;
            if (Int32.Parse(claim.Value) >= 50) return true;
            return false;
        });
    });

    config.DefaultPolicy = new AuthorizationPolicyBuilder()
              .RequireAuthenticatedUser()
              .Build();
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.DocumentTitle = "SwaggerJWTProject";
        c.RoutePrefix = "swagger";
        c.SwaggerEndpoint("v1/swagger.json", "v1");
        c.SwaggerEndpoint("v2/swagger.json", "v2");
        c.DocExpansion(DocExpansion.List);
    });
}

app.UseHttpsRedirection();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

#region Swagger configurations

/// <summary>
///     Swagger configuration.
/// </summary>
/// <param name="options">Option instances for configuring Swagger.</param>
void ConfigureSwaggerGen(SwaggerGenOptions options)
{
    var projectAssemblyName = _configuration.GetValue<string>("ServiceName");

    // add JWT Authentication
    var securityScheme = new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Description = "JWT Authorization header using the Bearer scheme. \r\n\r\n Enter 'Bearer' [space] and then your token in the text input below.\r\n\r\nExample: Bearer 1safsfsdfdfd",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "bearer", // must be lower case
        BearerFormat = "JWT",
        Reference = new OpenApiReference
        {
            Id = JwtBearerDefaults.AuthenticationScheme,
            Type = ReferenceType.SecurityScheme
        }
    };

    options.AddSecurityDefinition(securityScheme.Reference.Id, securityScheme);
    options.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {securityScheme, new string[] { }}
                });

    // add Access-Token Custom Authentication
    var securityScheme2 = new OpenApiSecurityScheme
    {
        Name = "Custom-Access-Token",
        Description = "Enter Access-Token token **_only_**",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "custom-access-token-scheme", // must be lower case
        Reference = new OpenApiReference
        {
            Id = "Custom-Access-Token",
            Type = ReferenceType.SecurityScheme
        }
    };

    options.AddSecurityDefinition(securityScheme2.Reference.Id, securityScheme2);
    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {securityScheme2, new string[] { }}
    });

    options.SwaggerDoc("v1", new OpenApiInfo { Title = projectAssemblyName, Version = "v1" });
    //options.SwaggerDoc("v2", new OpenApiInfo { Title = projectAssemblyName, Version = "v2" });

}

#endregion Swagger configurations
