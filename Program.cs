using DataTrust.Data;
using DataTrust.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Security.Claims;
using Azure.Identity;
using Azure.Extensions.AspNetCore.Configuration.Secrets;

var builder = WebApplication.CreateBuilder(args);

// Get connection string from Key Vault
var keyVaultUrl = builder.Configuration["KeyVaultUri"];
if (!string.IsNullOrEmpty(keyVaultUrl))
{
    builder.Configuration.AddAzureKeyVault(new Uri(keyVaultUrl), new DefaultAzureCredential());
}

// Fetch Google ClientId and ClientSecret from Key Vault
var googleClientId = builder.Configuration["GoogleClientId"];
var googleClientSecret = builder.Configuration["GoogleClientSecret"];

if (string.IsNullOrEmpty(googleClientId) || string.IsNullOrEmpty(googleClientSecret))
{
    throw new InvalidOperationException("Google ClientId and ClientSecret must be provided.");
}

builder.Services.AddDbContext<AppDbContext>(options => options.UseSqlServer(builder.Configuration["DefaultConnection"]));

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = "Google";
})
.AddCookie(options =>
{
    // When a user logs in to Google for the first time, create a local account for that user in our database.
    options.Events.OnValidatePrincipal += async context =>
    {
        var serviceProvider = context.HttpContext.RequestServices;
        using var db = new AppDbContext(serviceProvider.GetRequiredService<DbContextOptions<AppDbContext>>());

        var principal = context.Principal;
        if (principal == null)
        {
            context.RejectPrincipal();
            return;
        }

        string subject = principal.FindFirstValue(ClaimTypes.NameIdentifier) ?? throw new InvalidOperationException("NameIdentifier claim is missing.");
        string issuer = principal.FindFirst(ClaimTypes.NameIdentifier)?.Issuer ?? throw new InvalidOperationException("Issuer is missing.");
        string name = principal.FindFirst(ClaimTypes.Name)?.Value ?? throw new InvalidOperationException("Name claim is missing.");

        var account = db.Accounts.FirstOrDefault(p => p.OpenIDIssuer == issuer && p.OpenIDSubject == subject);

        if (account == null)
        {
            account = new Account
            {
                OpenIDIssuer = issuer,
                OpenIDSubject = subject,
                Name = name
            };
            db.Accounts.Add(account);
        }
        else
        {
            // If the account already exists, just update the name in case it has changed.
            account.Name = name;
        }

        await db.SaveChangesAsync();
    };
})
.AddOpenIdConnect("Google", options =>
{
    options.Authority = "https://accounts.google.com";
    options.ClientId = googleClientId;
    options.ClientSecret = googleClientSecret;
    options.ResponseType = OpenIdConnectResponseType.Code;
    options.CallbackPath = "/signin-oidc-google";
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.Scope.Add("email");
    options.SaveTokens = true;
    options.GetClaimsFromUserInfoEndpoint = true;

    options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "sub");
    options.ClaimActions.MapJsonKey(ClaimTypes.Name, "name");
});

builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
});

builder.Services.AddRazorPages().AddRazorRuntimeCompilation();
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<AccessControl>();
builder.Services.Configure<Microsoft.ApplicationInsights.Extensibility.TelemetryConfiguration>(config =>
{
    config.SetAzureTokenCredential(new DefaultAzureCredential());
});

builder.Services.AddApplicationInsightsTelemetry(new Microsoft.ApplicationInsights.AspNetCore.Extensions.ApplicationInsightsServiceOptions
{
    ConnectionString = builder.Configuration["APPLICATIONINSIGHTS_CONNECTION_STRING"]
});

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapRazorPages();
app.MapControllers();

using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var context = services.GetRequiredService<AppDbContext>();
    SampleData.Create(context);
}

app.Run();
