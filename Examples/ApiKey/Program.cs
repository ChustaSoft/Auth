using ChustaSoft.Auth.ApiKey;

var builder = WebApplication.CreateBuilder(args);

// Option 1: Using the extension method with a simple lambda function as the token provider
//builder.Services.ConfigureApiKeyAuthentication((token) => { return token == "Test_ApiKey"; });

// Option 2: Using the extension method with a custom token provider class that implements the ITokenProvider interface
builder.Services.ConfigureApiKeyAuthentication<InternalTokenProvider>();

var app = builder.Build();

app.UseHttpsRedirection();

var summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
};

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/weatherforecast", () =>
{
    var forecast = Enumerable.Range(1, 5).Select(index =>
        new WeatherForecast
        (
            DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            Random.Shared.Next(-20, 55),
            summaries[Random.Shared.Next(summaries.Length)]
        ))
        .ToArray();
    return forecast;
}).RequireAuthorization();

app.Run();


public class InternalTokenProvider : ITokenProvider
{
    public bool Validate(string token)
    {
        return token == "Test_ApiKey";
    }
}