# ChustaSoft.Auth.Basic
---

## Description

This library encapsulates the logic for handling Basic authentication in a .NET application. 
It provides a simple way to validate username and password credentials and integrate them into the authentication pipeline of an application.


## How to integrate

### Configuring the AuthenticationHandler

The recommended way to handle it is through the built in AuthenticationHandler. The project will require to configure its own ApiKey Token Provider. 
This will allow the project to configure them isolated from the auth library, and the library is just expecting a function for that in order to validate the token against.

#### Option A: Using a lambda function

```csharp
	builder.Services.ConfigureBasicAuthentication((username, password) 
		=> { return username == "test" && password == "pass"; });
```

#### Option B: Using a separate class
```csharp
// Implementing the ICredentialsProvider interface
public class InternalCredentialsProvider : ICredentialsProvider
{
    public bool Validate(string username, string password)
    {
        return username == "test" && password == "pass";
    }
}


// In the configuration
builder.Services.ConfigureBasicAuthentication<InternalCredentialsProvider>();
```

This provider can be implemented in multiple ways, including another service as long as it complies with the signature of the function.

Check the sample project [here](https://github.com/ChustaSoft/Auth/tree/main/Examples/Basic)


*Thanks for using and contributing*
---
