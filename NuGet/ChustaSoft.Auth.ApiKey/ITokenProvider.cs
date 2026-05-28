namespace ChustaSoft.Auth.ApiKey;

public interface ITokenProvider 
{
    bool Validate(string token);
}