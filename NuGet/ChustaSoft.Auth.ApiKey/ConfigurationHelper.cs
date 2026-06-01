using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace ChustaSoft.Auth.ApiKey;


public static class ConfigurationHelper
{
    /// <summary>
    /// Adds API key authentication and authorization to the specified service collection using the provided token
    /// validator and authentication scheme name.
    /// </summary>
    /// <remarks>Registers the provided token validator as a transient Func<string,bool> and adds
    /// ApiKeyAuthenticationHandler under the specified scheme.</remarks>
    /// <param name="services">The IServiceCollection to register authentication and authorization services with.</param>
    /// <param name="apiKeyTokenProvider">A function that validates an API key token and returns true when the token is valid.</param>
    /// <param name="schemaName">The authentication scheme name to register; defaults to "ApiKeyAuthentication".</param>
    public static void ConfigureApiKeyAuthentication(this IServiceCollection services, Func<string, bool> apiKeyTokenProvider, string schemaName = "ApiKeyAuthentication")
    {
        services.AddTransient<Func<string, bool>>(x => apiKeyTokenProvider);

        services.AddAuthentication(schemaName)
            .AddScheme<AuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(schemaName, null);

        services.AddAuthorization();
    }


    /// <summary>
    /// Adds API key authentication and authorization to the service collection and configures the specified
    /// authentication scheme.
    /// </summary>
    /// <remarks>Registers TProvider as an ITokenProvider (transient), exposes a Func<string,bool> that
    /// delegates to ITokenProvider.Validate, adds an authentication scheme using ApiKeyAuthenticationHandler, and
    /// enables authorization.</remarks>
    /// <typeparam name="TProvider">The token provider type used to validate API keys; must implement ITokenProvider and is registered with
    /// transient lifetime.</typeparam>
    /// <param name="services">The IServiceCollection to configure with the token provider, authentication scheme, and authorization services.</param>
    /// <param name="schemaName">The name of the authentication scheme to register for API key authentication. Defaults to
    /// "ApiKeyAuthentication".</param>
    public static void ConfigureApiKeyAuthentication<TProvider>(this IServiceCollection services, string schemaName = "ApiKeyAuthentication")
        where TProvider : class, ITokenProvider
    {
        services.AddTransient<ITokenProvider, TProvider>();
        services.AddTransient<Func<string, bool>>(x => x.GetRequiredService<ITokenProvider>().Validate);

        services.AddAuthentication(schemaName)
            .AddScheme<AuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(schemaName, null);
    }

}
