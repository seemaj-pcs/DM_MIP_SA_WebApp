using DM_MIP_SA_WebApp.Models;
using DM_MIP_SA_WebApp.Services;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Client;
using Microsoft.InformationProtection;

namespace DM_MIP_SA_WebApp.Services
{
    internal class AuthDelegateImpl : IAuthDelegate
    {
        private readonly AuthService _authService;

        // userAssertionToken = incoming API access token (from Authorization: Bearer ...)
        public AuthDelegateImpl(AuthService authService)
        {
            _authService = authService ?? throw new ArgumentNullException(nameof(authService));
            
        }

        // Called by the MIP SDK when it needs a token
        public string AcquireToken(Identity identity, string authority, string resource, string claims)
        {
            Console.WriteLine(
                $"MIP SDK requesting token - Identity: {identity}, Authority: {authority}, Resource: {resource}");

            // Same pattern as your console app:
            // Turn a resource like "https://api.aadrm.com" into "https://api.aadrm.com/.default"
            //string[] scopes = new string[]
            //{
            //    resource[resource.Length - 1].Equals('/')
            //        ? $"{resource}.default"
            //        : $"{resource}/.default"
            //};

            
            
            // For the web API, instead of interactive sign-in we do OBO:
            // use the incoming API token (_userAssertionToken) as the user assertion.
            var token = _authService
                .AcquireToken(new[] { $"{resource}/.default" })
                .GetAwaiter()
                .GetResult();

            Console.WriteLine($"Successfully acquired  token for MIP SDK --- {token}");
            return token;
        }
    }
}