using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace ChustaSoft.Auth.ApiKey;


public static class ConfigurationHelper
{
    public static void ConfigureApiKeyAuthentication(this IServiceCollection services, Func<string, bool> apiKeyTokenProvider, string schemaName = "ApiKeyAuthentication")
    {
        services.AddTransient<Func<string, bool>>(x => apiKeyTokenProvider);

        services.AddAuthentication(schemaName)
            .AddScheme<AuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(schemaName, null);
    }
}
