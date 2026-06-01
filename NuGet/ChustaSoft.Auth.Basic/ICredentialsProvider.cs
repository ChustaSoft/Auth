namespace ChustaSoft.Auth.ApiKey;

public interface ICredentialsProvider
{
    bool Validate(string username, string password);
}