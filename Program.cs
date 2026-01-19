using DM_MIP_SA_WebApp.Models;
using DM_MIP_SA_WebApp.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Identity.Web;
using static System.Net.WebRequestMethods;

namespace DM_MIP_SA_WebApp
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            var configuration = builder.Configuration;

            // Bind configuration into strongly typed option classes
            builder.Services.Configure<AzureAdOptions>(configuration.GetSection("AzureAd"));
            builder.Services.Configure<MipSdkOptions>(configuration.GetSection("MipSdk"));
            builder.Services.Configure<EmailOptions>(configuration.GetSection("Email"));

            string[] allowedOrigins = new[] { "http://localhost:5173", "https://oauth.pstmn.io/v1/callback"}; // Add all necessary origin
            builder.Services.AddCors(options =>
            {
                options.AddPolicy("AllowFrontend",
                    policy =>
                    {
                        policy.WithOrigins(allowedOrigins) // React app
                              .AllowAnyHeader()
                              .AllowAnyMethod()
                              .AllowCredentials();
                    });
            });
            // Register application services
            builder.Services.AddScoped<AuthService>();
            builder.Services.AddScoped<EmailService>();
            builder.Services.AddScoped<IFileService, FileService>();
            

            // MVC / Controllers
            builder.Services.AddControllers();

            var app = builder.Build();

            //app.UseHttpsRedirection();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseCors("AllowFrontend");
            app.MapControllers();
            
            app.Run();
        }
    }
}