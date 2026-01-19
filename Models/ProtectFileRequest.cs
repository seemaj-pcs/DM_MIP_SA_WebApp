namespace DM_MIP_SA_WebApp.Models
{
    public class ProtectFileRequest
    {
        public required IFormFile File {  get; set; }

        public required string Email { get; set; } = string.Empty;

        public required string OwnerEmail { get; set; } = string.Empty;

        public required bool SendEmail { get; set; } = true;
        // e.g. ["Read", "Edit", "Print", "FullControl", "Share"]
        public required string Rights { get; set; } = string.Empty;

        public bool? RetainInputFiles { get; set; }
        public bool? RetainOutputFiles { get; set; }
    }
}
