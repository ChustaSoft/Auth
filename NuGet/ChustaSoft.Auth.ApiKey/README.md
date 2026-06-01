# ChustaSoft.Auth.ApiKey
---

## Description

This library encapsulates the logic for handling API Key authentication in a .NET application. 
It provides a simple way to validate API keys and integrate them into the authentication pipeline of an application.


## How to integrate

### Configuring the AuthenticationHandler

The recommended way to handle it is through the built in AuthenticationHandler. The project will require to configure its own ApiKey Token Provider. 
This will allow the project to configure them isolated from the auth library, and the library is just expecting a function for that in order to validate the token against.

#### Option A: Using a lambda function

```csharp
	builder.Services.ConfigureApiKeyAuthentication((token) 
		=> { return token == "Test_ApiKey"; });


```


#### Option B: Using a separate class
```csharp
// Implementing the ITokenProvider interface
public class InternalTokenProvider : ITokenProvider
{
    public bool Validate(string token)
    {
        return token == "Test_ApiKey";
    }
}

// In the configuration
builder.Services.ConfigureApiKeyAuthentication<InternalTokenProvider>();
```

This provider can be implemented in multiple ways, for example with a custom provider inyecting a IOptionsMonitor to get the valid tokens from configuration, or even with a provider that gets the valid tokens from a database or an external service.

Check the sample project [here](https://github.com/ChustaSoft/Auth/tree/main/Examples/ApiKey)


*Thanks for using and contributing*
---
