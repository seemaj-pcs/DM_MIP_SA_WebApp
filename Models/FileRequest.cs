namespace DM_MIP_SA_WebApp.Models
{
    public class FileRequest
    {
        public IFormFile? File {  get; set; }
        public string FileName {  get; set; } = string.Empty;

        public string FileBase64StringContent { get; set; } = string.Empty;

        public string Email { get; set; } = string.Empty;

        public string OwnerEmailId { get; set; } = string.Empty;

        private string fileAccessRightType = null;

        public string FileAccessRightType   // property
        {
            get { return fileAccessRightType; }   // get method
            set { fileAccessRightType = value; }  // set method
        }
    }
}
