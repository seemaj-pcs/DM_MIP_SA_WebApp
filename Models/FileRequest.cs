namespace DM_MIP_SA_WebApp.Models
{
    public class FileRequest
    {
        public IFormFile? File {  get; set; }
        public string FileName {  get; set; } = string.Empty;

        public string FileBase64StringContent { get; set; } = string.Empty;

        public string Email { get; set; } = string.Empty;

        public string OwnerEmailId { get; set; } = string.Empty;

        public string FileAccessRightType { get; set; } = string.Empty;

    }
}
