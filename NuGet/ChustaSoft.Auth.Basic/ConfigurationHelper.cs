using ChustaSoft.Auth.ApiKey;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace ChustaSoft.Auth.Basic;


public static class ConfigurationHelper
{

    /// <summary>
    /// Configures basic authentication by registering a credentials provider and adding an authentication scheme.  
    /// </summary>
    /// <remarks>Registers the provided delegate as a transient Func<string,string,bool> and adds an authentication
    /// scheme that uses BasicAuthenticationHandler.</remarks>
    /// <param name="services">The service collection to add authentication services to.</param>
    /// <param name="userCredentialsProvider">A delegate that validates a username and password and returns true for valid credentials.</param>
    /// <param name="schemaName">The name of the authentication scheme to register; defaults to "BasicAuthentication".</param>
    public static void ConfigureBasicAuthentication(this IServiceCollection services, Func<string, string, bool> userCredentialsProvider, string schemaName = "BasicAuthentication")
    {
        services.AddTransient<Func<string, string, bool>>(x => userCredentialsProvider);

        services.AddAuthentication(schemaName)
            .AddScheme<AuthenticationSchemeOptions, BasicAuthenticationHandler>(schemaName, null);
    }


    /// <summary>
    /// Registers an ICredentialsProvider and a credentials validation delegate, configures an authentication scheme
    /// backed by BasicAuthenticationHandler using the specified scheme name, and adds authorization services.
    /// </summary>
    /// <remarks>Credentials provider and validation delegate are registered as transient services. The method
    /// adds an authentication scheme with AuthenticationSchemeOptions and BasicAuthenticationHandler and then enables
    /// authorization.</remarks>
    /// <typeparam name="TProvider">The ICredentialsProvider implementation type to register as a transient service.</typeparam>
    /// <param name="services">The IServiceCollection to configure with authentication and authorization services.</param>
    /// <param name="schemaName">The authentication scheme name to register; defaults to "BasicAuthentication".</param>
    public static void ConfigureBasicAuthentication<TProvider>(this IServiceCollection services, string schemaName = "BasicAuthentication")
        where TProvider : class, ICredentialsProvider
    {
        services.AddTransient<ICredentialsProvider, TProvider>();
        services.AddTransient<Func<string, string, bool>>(x => x.GetRequiredService<ICredentialsProvider>().Validate);

        services.AddAuthentication(schemaName)
            .AddScheme<AuthenticationSchemeOptions, BasicAuthenticationHandler>(schemaName, null);

        services.AddAuthorization();
    }
}
