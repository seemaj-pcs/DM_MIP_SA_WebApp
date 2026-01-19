using Microsoft.Extensions.Options;
using Microsoft.Identity.Client;
using DM_MIP_SA_WebApp.Models;
using System.IdentityModel.Tokens.Jwt;

namespace DM_MIP_SA_WebApp.Services
{
    public class AuthService
    {
        private readonly AzureAdOptions _azureAd;
        private readonly MipSdkOptions _mipOptions;
        private readonly IConfidentialClientApplication _cca;
        private readonly string[] _defaultScopes;
        private readonly ILogger<AuthService> _logger;

        public AuthService(
            IOptions<AzureAdOptions> azureAdOptions,
            IOptions<MipSdkOptions> mipOptions,
            ILogger<AuthService> logger)
        {
            _azureAd = azureAdOptions.Value;
            _mipOptions = mipOptions.Value;
            _logger = logger;

            var authority = $"{_azureAd.Instance.TrimEnd('/')}/{_azureAd.TenantId}";

            _cca = ConfidentialClientApplicationBuilder
                .Create(_azureAd.ClientId)
                .WithClientSecret(_azureAd.ClientSecret)
                .WithAuthority(authority)
                .Build();

            _defaultScopes = !string.IsNullOrWhiteSpace(_mipOptions.Scopes)
                ? _mipOptions.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                : new[] { $"{_azureAd.ClientId}/.default" };

            _logger.LogInformation("AuthService initialized with default scopes: {Scopes}", string.Join(", ", _defaultScopes));
        }

        // OBO equivalent of SignInUserAndGetAccessTokenUsingMSAL
        public async Task<string> AcquireToken(string[]? scopes = null)
        {
            var result = _cca
                    .AcquireTokenForClient(scopes)
                    .ExecuteAsync()
                    .GetAwaiter()
                    .GetResult();

            // Log token details
            LogTokenDetails(result.AccessToken, "Token");

            return result.AccessToken;
        }

        private void LogTokenDetails(string accessToken, string tokenType)
        {
            try
            {
                var jwtHandler = new JwtSecurityTokenHandler();
                if (jwtHandler.CanReadToken(accessToken))
                {
                    var jwtToken = jwtHandler.ReadJwtToken(accessToken);

                    _logger.LogInformation(
                        "{TokenType} Details - Subject: {Subject}, Audience: {Audience}, Scopes: {Scp}, Expires: {Exp}",
                        tokenType,
                        jwtToken.Subject,
                        string.Join(", ", jwtToken.Audiences),
                        jwtToken.Claims.FirstOrDefault(c => c.Type == "scp")?.Value ?? "N/A",
                        jwtToken.ValidTo.ToString("O"));

                    _logger.LogDebug("{TokenType} (truncated): {Token}...", tokenType, accessToken.Substring(0, Math.Min(50, accessToken.Length)));
                }
                else
                {
                    _logger.LogWarning("Unable to parse {TokenType} as JWT", tokenType);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error logging token details for {TokenType}", tokenType);
            }
        }
    }
}
