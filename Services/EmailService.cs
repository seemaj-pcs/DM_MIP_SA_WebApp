using Azure.Core;
using Azure.Identity;
using DM_MIP_SA_WebApp.Models;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Microsoft.Identity.Client;
using System.Security.Claims;

namespace DM_MIP_SA_WebApp.Services
{
    public class EmailService
    {
        public async Task<string> sendEmail(AzureAdOptions azureOptions, 
                    EmailOptions emailOptions, string fileName, string recepient)
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

            Console.WriteLine($"graphAccessToken - {graphAccessToken}");

            // 4. Initialize Graph Client
            //var options = new OnBehalfOfCredentialOptions
            //{
            //    AuthorityHost = AzureAuthorityHosts.AzurePublicCloud,
            //};

            //// The OBO credential exchanges the user token for a new token
            //var onBehalfOfCredential = new OnBehalfOfCredential(
            //    azureOptions.TenantId, azureOptions.ClientId, azureOptions.ClientSecret, userToken, options);
            //var graphClient = new GraphServiceClient(onBehalfOfCredential);

            
            // The credential exchanges the user token for a new token
            var onBehalfOfCredential = new ClientSecretCredential(
                azureOptions.TenantId, azureOptions.ClientId, azureOptions.ClientSecret);
            var graphClient = new GraphServiceClient(onBehalfOfCredential);

            Console.WriteLine($"graphClient - {graphClient}");

            // 5. Read file and convert to Base64

            byte[] fileBytes = System.IO.File.ReadAllBytes(fileName);
            string base64File = Convert.ToBase64String(fileBytes);

            var ext = Path.GetExtension(fileName); // returns .exe
            var fname = Path.GetFileNameWithoutExtension(fileName);

            // 6. Create the message

            var requestBody = new Microsoft.Graph.Me.SendMail.SendMailPostRequestBody
            {
                Message = new Message
                {
                    Subject = emailOptions.Subject,
                    Body = new ItemBody { Content = emailOptions.Contents, ContentType = Microsoft.Graph.Models.BodyType.Text },
                    ToRecipients = new List<Recipient> { 
                            new Recipient { EmailAddress = new EmailAddress { Address = recepient } } },
                    Attachments = new List<Attachment>
                    {
                        new FileAttachment
                        {
                            OdataType = "#microsoft.graph.fileAttachment",
                            Name = fname + ext,
                            ContentType = "text/plain",
                            ContentBytes = fileBytes // SDK handles byte array to base64 conversion
                        }
                    }
                },
                SaveToSentItems = true
            };

            Console.WriteLine("Sending email--------------!");
            // 7. Send the mail
            graphClient.Me.SendMail.PostAsync(requestBody);
            Console.WriteLine("Email sent successfully!");
            return "Email sent successfully";
        }
    }
}
