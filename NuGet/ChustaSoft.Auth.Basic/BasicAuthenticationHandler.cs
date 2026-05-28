using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace ChustaSoft.Auth.Basic;


/// <summary>
/// Handles HTTP Basic authentication by validating the Authorization header, decoding base64 username:password
/// credentials, invoking a credentials provider, and producing an authenticated ClaimsPrincipal when valid.
/// </summary>
/// <remarks>Skips authentication for endpoints with IAllowAnonymous metadata. Expects an Authorization header
/// with the Basic scheme and base64-encoded credentials separated by ':'. Uses the provided Func<string,string,bool> to
/// validate credentials and fails when header parsing or validation fails. On success, issues a ClaimsIdentity
/// containing ClaimTypes.Name and an AuthenticationTicket for the configured scheme.</remarks>
public class BasicAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{

    private readonly Func<string, string, bool> _userCredentialsProvider;


    public BasicAuthenticationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, Func<string, string, bool> userCredentialsProvider)
        : base(options, logger, encoder)
    {
        _userCredentialsProvider = userCredentialsProvider;
    }


    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        return await Task.Run(() =>
        {
            var endpoint = Context.GetEndpoint();
            if (endpoint?.Metadata?.GetMetadata<IAllowAnonymous>() != null)
                return AuthenticateResult.NoResult();

            if (!Request.Headers.TryGetValue("Authorization", out var value))
                return AuthenticateResult.Fail("Missing Authorization Header");

            var authResult = false;
            string username, password = string.Empty;
            try
            {
                var authHeader = AuthenticationHeaderValue.Parse(value!);
                var credentialBytes = Convert.FromBase64String(authHeader.Parameter ?? string.Empty);
                var credentials = Encoding.UTF8.GetString(credentialBytes).Split(new[] { ':' }, 2);
                username = credentials[0];
                password = credentials[1];

                authResult = _userCredentialsProvider.Invoke(username, password);
            }
            catch
            {
                return AuthenticateResult.Fail("Invalid Authorization Header");
            }

            if (!authResult)
                return AuthenticateResult.Fail("Invalid Username or Password");

            var claims = new[] {
                new Claim(ClaimTypes.Name, username),
            };

            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            return AuthenticateResult.Success(ticket);
        });
    }

}
