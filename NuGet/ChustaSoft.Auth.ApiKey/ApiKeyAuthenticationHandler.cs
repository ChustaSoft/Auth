using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace ChustaSoft.Auth.ApiKey;


/// <summary>
/// Authenticates requests by validating an API key supplied in the X-ApiKey request header and, on success, produces an
/// AuthenticationTicket for the configured authentication scheme.
/// </summary>
/// <remarks>Derived from AuthenticationHandler<AuthenticationSchemeOptions>. Validation is delegated to a
/// provided Func<string,bool>. If the endpoint has IAllowAnonymous metadata, authentication is skipped (NoResult).
/// Missing header, invalid key, or exceptions during validation result in AuthenticateResult.Fail. On success a
/// ClaimsPrincipal containing a ClaimTypes.Name claim with value "Valid API" is created and returned in an
/// AuthenticationTicket. Register this handler in the authentication pipeline and supply a key-validation
/// delegate.</remarks>
public class ApiKeyAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{

    private readonly Func<string, bool> _apiKeyTokenProvider; //TODO: Allow to match a client by URL with its API Key


    public ApiKeyAuthenticationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, Func<string, bool> userCredentialsProvider)
        : base(options, logger, encoder)
    {
        _apiKeyTokenProvider = userCredentialsProvider;
    }


    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        return await Task.Run(() =>
        {
            var endpoint = Context.GetEndpoint();
            if (endpoint?.Metadata?.GetMetadata<IAllowAnonymous>() != null)
                return AuthenticateResult.NoResult();

            if (!Request.Headers.TryGetValue("X-ApiKey", out var extractedApiKey))
                return AuthenticateResult.Fail("Missing X-ApiKey Authorization Header");

            var authResult = false;
            try
            {
                authResult = _apiKeyTokenProvider.Invoke(extractedApiKey!);
            }
            catch
            {
                return AuthenticateResult.Fail("Unexpected error authenticating request");
            }

            if (!authResult)
                return AuthenticateResult.Fail("Invalid X-ApiKey");

            var claims = new[] {
                new Claim(ClaimTypes.Name, "Valid API"),
            };

            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            return AuthenticateResult.Success(ticket);
        });
    }

}
