﻿using ChustaSoft.Auth.Basic.Handlers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace ChustaSoft.Auth.Basic.Configuration;


public static class ConfigurationHelper
{
    public static void ConfigureBasicAuthentication(this IServiceCollection services, Func<string, string, bool> userCredentialsProvider, string schemaName = "BasicAuthentication")
    {
        services.AddTransient<Func<string, string, bool>>(x => userCredentialsProvider);

        services.AddAuthentication(schemaName)
            .AddScheme<AuthenticationSchemeOptions, BasicAuthenticationHandler>(schemaName, null);
    }
}
