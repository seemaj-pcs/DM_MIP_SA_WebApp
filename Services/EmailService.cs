using Azure.Core;
using Azure.Identity;
using DM_MIP_SA_WebApp.Models;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Microsoft.Identity.Client;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Net.Http;
using System.Text;

namespace DM_MIP_SA_WebApp.Services
{
    public class EmailService
    {
        public async Task<string> sendEmail(AzureAdOptions azureOptions,
            MipSdkOptions mipSdkOptions, EmailOptions emailOptions, 
            string fileName, string recepient, string subject, string action)
        {
            // 2. Configure MSAL for OBO
            IConfidentialClientApplication confidentialClient = ConfidentialClientApplicationBuilder.Create(azureOptions.ClientId)
                .WithClientSecret(azureOptions.ClientSecret)
                .WithTenantId(azureOptions.TenantId)
                .Build();

            // 3. Exchange the token
            var oboResult = confidentialClient.AcquireTokenForClient(
                new[] { "https://graph.microsoft.com/.default" }
                )
                .ExecuteAsync();

            string graphAccessToken = oboResult.Result.AccessToken;

            Console.WriteLine($"UserToke - {graphAccessToken}");

            var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", graphAccessToken);

            subject = "Notification - " + subject;
            var contents = emailOptions.Contents;
            contents = contents.Replace("{fileName}", Path.GetFileName(fileName));
            contents = contents.Replace("{action}", Path.GetFileName(action));

            var emailPayload = new
            {
                message = new
                {
                    subject = subject,
                    body = new
                    {
                        contentType = "Text",
                        content = contents
                    },
                    toRecipients = new[]
                    {
                        new
                        {
                            emailAddress = new
                            {
                                address = recepient
                            }
                        }
                    }
                },
                saveToSentItems = true
            };

            var json = System.Text.Json.JsonSerializer.Serialize(emailPayload);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            Console.WriteLine("Sending email--------------!");
            var response = await httpClient.PostAsync(
                "https://graph.microsoft.com/v1.0/users/" + mipSdkOptions.ServiceAccountEmail+ "/sendMail",
                content);

            response.EnsureSuccessStatusCode();

            // 7. Send the mail

            Console.WriteLine("Email sent successfully!");
            return "Email sent successfully";

        }
    }
}
