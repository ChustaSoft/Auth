using ChustaSoft.Auth.ApiKey;
using ChustaSoft.Auth.Basic;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

// Option 1: Using the extension method with a simple lambda function as the credentials provider
//builder.Services.ConfigureBasicAuthentication((username, password) => { return username == "test" && password == "pass"; });

// Option 2: Using the extension method with a custom credentials provider class that implements the ICredentialsProvider interface
builder.Services.ConfigureBasicAuthentication<InternalCredentialsProvider>();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();


var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();


public class InternalCredentialsProvider : ICredentialsProvider
{
    public bool Validate(string username, string password)
    {
        return username == "test" && password == "pass";
    }
}
