using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading;
using ChustaSoft.Auth.ApiKey;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using Xunit;

public class ApiKeyAuthenticationHandlerTests
{
    [Fact]
    public async Task HandleAuthenticateAsync_ShouldFail_WhenApiKeyHeaderIsMissing()
    {
        // Arrange
        var handler = CreateHandler((key) => true);

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal("Missing X-ApiKey Authorization Header", result.Failure.Message);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ShouldFail_WhenApiKeyIsInvalid()
    {
        // Arrange
        var handler = CreateHandler((key) => false, "invalid_key");

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal("Invalid X-ApiKey", result.Failure.Message);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ShouldSucceed_WhenApiKeyIsValid()
    {
        // Arrange
        var handler = CreateHandler((key) => true, "valid_key");

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        Assert.True(result.Succeeded);
        var claimsIdentity = result.Principal.Identity as ClaimsIdentity;
        Assert.NotNull(claimsIdentity);
        Assert.Equal("Valid API", claimsIdentity.Name);
    }

    private ApiKeyAuthenticationHandler CreateHandler(Func<string, bool> apiKeyValidator, string? token = null)
    {
        var optionsMonitor = Substitute.For<IOptionsMonitor<AuthenticationSchemeOptions>>();
        var logger = Substitute.For<ILoggerFactory>();
        var urlEncoder = Substitute.For<UrlEncoder>();
        var handler = new ApiKeyAuthenticationHandler(optionsMonitor, logger, urlEncoder, apiKeyValidator);

        var context = new DefaultHttpContext();

        if (!string.IsNullOrEmpty(token))
            context.Request.Headers["X-ApiKey"] = token;

        handler.InitializeAsync(
            new AuthenticationScheme("ApiKey", null, typeof(ApiKeyAuthenticationHandler)),
            context
        ).Wait();

        return handler;
    }
}