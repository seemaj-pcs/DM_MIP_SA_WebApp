namespace DM_MIP_SA_WebApp.Models
{
    public class MipSdkOptions
    {
        public string AppId { get; set; } = string.Empty;
        public string AppName { get; set; } = string.Empty;
        public string AppVersion { get; set; } = string.Empty;
        public string EnableEml { get; set; } = "false";
        public string CachePath { get; set; } = "c:\\mip-cache";
        public string Scopes { get; set; } = string.Empty; // MIP resource scopes

        public string EngineId { get; set; } = string.Empty;

        public string ServiceAccountEmail {  get; set; } = string.Empty;
        public string InputFolder {  get; set; } = string.Empty;
        public string ProtectedFileFolder { get; set; } = string.Empty;
        public string UnprotectedFileFolder { get; set; } = string.Empty;

        public string LabelToApply {  get; set; } = string.Empty;

        public bool SendEmail { get; set; } = false;
        public bool RetainInputFiles { get; set; } = false;
        public bool RetainOutputFiles { get; set; } = false;

        public Dictionary<string, string> FileRights { get; set; }

        public string UnsupportedFileExtensions {  get; set; }   = string.Empty;

    }
}
