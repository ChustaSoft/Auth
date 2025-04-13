# ChustaSoft.Auth.ApiKey
---

## Description

_TBD_



## How to integrate

### Configuring the AuthenticationHandler

The recommended way to handle it is through the built in AuthenticationHandler. The project will require to configure its own ApiKey Token Provider. 
This will allow the project to configure them isolated from the auth library, and the library is just expecting a function for that in order to validate the token against.

```csharp
	builder.Services.ConfigureBasicAuthentication((username, password) 
		=> { return username == "test" && password == "pass"; });
```

This provider can be implemented in multiple ways, including another service as long as it complies with the signature of the function.


*Thanks for using and contributing*
---
