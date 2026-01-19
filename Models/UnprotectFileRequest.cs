namespace DM_MIP_SA_WebApp.Models
{
    public class UnprotectFileRequest
    {
        public required IFormFile File {  get; set; }

        public bool? RetainInputFiles { get; set; }
        public bool? RetainOutputFiles { get; set; }
    }
}
