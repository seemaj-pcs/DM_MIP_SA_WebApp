using System.Net;

namespace DM_MIP_SA_WebApp.Models
{
    public class FileResponse
    {
        //public string Name {  get; set; } = string.Empty;

        //public FileRequest OriginalRequest { get; set; } = null;

        //public string Status { get; set; } = string.Empty;

        //public string Message { get; set; } = string.Empty;

        //public HttpStatusCode Code{ get; set; } = HttpStatusCode.OK;

        //public string Body { get; set; } = string.Empty;

        public HttpStatusCode StatusCode { get; set; } = HttpStatusCode.OK;
        public string StatusMessage { get; set; } = string.Empty;

        public string FileResponseContent { get; set; } = string.Empty;
    }
}
