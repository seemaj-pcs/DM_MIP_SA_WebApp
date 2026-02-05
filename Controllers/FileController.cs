using DM_MIP_SA_WebApp.Models;
using DM_MIP_SA_WebApp.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder.Extensions;
using Microsoft.AspNetCore.Mvc;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace DM_MIP_SA_WebApp.Controllers
{
    [ApiController]
    [Route("api/FileProtection")]
    public class FileController : ControllerBase
    {
        private readonly IFileService _fileService;

        public FileController(IFileService fileSvc)
        {
            _fileService = fileSvc;
        }

        [HttpPost("GetProtectedFileDetailsWithFile")]
        [RequestSizeLimit(100_000_000)]
        public async Task<IActionResult> ProtectFileWithFile(
            [FromForm] FileRequest p)
        {
            return await ProtectFile(p, true);

        }
        [HttpPost("GetProtectedFileDetailsWithBase64File")]
        [RequestSizeLimit(100_000_000)]
        public async Task<IActionResult> ProtectFileWithBase64File(
            [FromBody] FileRequest p)
        {
            return await ProtectFile(p, false);
        }

        private async Task<IActionResult> ProtectFile(
            FileRequest p, bool isFile)
        {
            var resp = new FileResponse();
            string inputFileName = null;
            string outputFileName = null;
            try
            {
                ValidateRequest(p, isFile, true);

                if (p.FileName.Contains(".."))
                    throw new Exception("fileName is invalid.");

                List<String> rightList = p.FileAccessRightType.Split(",").ToList();

                var ext = Path.GetExtension(p.FileName); // returns .exe
                var fname = Path.GetFileNameWithoutExtension(p.FileName);
                var outputFile = fname + "_protected" + ext;

                var serviceIOFiles = await _fileService.ProtectFileAsync(
                    p,
                    outputFile);
                inputFileName = serviceIOFiles.InputFileName;
                outputFileName = serviceIOFiles.OutputFileName;
                ValidateFileName(outputFileName);

                // Return JSON metadata, not file bytes
                // Read unprotected file
                var protectedBytes = await System.IO.File.ReadAllBytesAsync(outputFileName);

                string fileBase64string = Convert.ToBase64String(protectedBytes);

                resp.StatusCode = HttpStatusCode.OK;
                resp.StatusMessage = "Success";
                resp.FileResponseContent = fileBase64string;

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.StackTrace);
                resp.StatusCode = HttpStatusCode.BadRequest;
                resp.StatusMessage = "Error :" + ex.Message;
                resp.FileResponseContent = "";
            }
            finally
            {
                CleanupFiles(inputFileName, outputFileName);
            }
            return Ok(resp);

        }

        [HttpPost("GetUnProtectedFileDetailsWithFile")]
        [RequestSizeLimit(100_000_000)]
        
        public async Task<IActionResult> UnprotectFileWithFile(
            [FromForm] FileRequest p)
        {
            return await UnprotectFile(p, true);
        }

        [HttpPost("GetUnProtectedFileDetailsWithBase64File")]
        [RequestSizeLimit(100_000_000)]
        
        public async Task<IActionResult> UnprotectFileWithBase64File(
            [FromBody] FileRequest p)
        {
            return await UnprotectFile(p, false);
        }

        private async Task<IActionResult> UnprotectFile(
            FileRequest p, bool isFile)
        {
            var resp = new FileResponse();
            string inputFileName = null;
            string outputFileName = null;
            try
            {
                ValidateRequest(p, isFile, false);

                var ext = Path.GetExtension(p.FileName); // returns .exe
                var fname = Path.GetFileNameWithoutExtension(p.FileName);
                var outputFile = fname + "_unprotected" + ext;
            
                var serviceIOFiles = await _fileService.UnprotectFileAsync(
                    p,
                    outputFile);
                
                inputFileName = serviceIOFiles.InputFileName;
                outputFileName = serviceIOFiles.OutputFileName;

                ValidateFileName(outputFileName);
                // Return JSON metadata, not file bytes
                // Read unprotected file
                var unprotectedBytes = await System.IO.File.ReadAllBytesAsync(outputFileName);

                string fileBase64string = Convert.ToBase64String(unprotectedBytes);

                resp.StatusCode = HttpStatusCode.OK;
                resp.StatusMessage = "Success";
                resp.FileResponseContent = fileBase64string;
                
            }
            catch (Exception ex)
            {
                resp.StatusCode = HttpStatusCode.BadRequest;
                resp.StatusMessage = "Error :" + ex.Message;
                resp.FileResponseContent = "";
            }
            finally
            {
                CleanupFiles(inputFileName, outputFileName);
            }
            return Ok(resp);
        }

        [HttpPost("AssignAdditionalUserPermissionsWithFile")]
        [RequestSizeLimit(100_000_000)]
        
        public async Task<IActionResult> UnprotectFileAssignAdditionalUserPermissionsWithFile(
            [FromForm] FileRequest p)
        {
            return await AdditionalProtectFile(p, true);
        }

        [HttpPost("AssignAdditionalUserPermissionsWithBase64File")]
        [RequestSizeLimit(100_000_000)]
        
        public async Task<IActionResult> AssignAdditionalUserPermissionsWithBase64File(
            [FromBody] FileRequest p)
        {
            return await AdditionalProtectFile(p, false);
        }

        
        private async Task<IActionResult> AdditionalProtectFile(
            FileRequest p, bool isFile)
        {
            var resp = new FileResponse();
            string inputFileName = null;
            string outputFileName = null;
            try
            {
                ValidateRequest(p, isFile, true);

                List<String> rightList = p.FileAccessRightType.Split(",").ToList();
                 
                var ext = Path.GetExtension(p.FileName); // returns .exe
                var fname = Path.GetFileNameWithoutExtension(p.FileName);
                var outputFile = fname + "_protected" + ext;
            
                var serviceIOFiles = await _fileService.AdditionalProtectFileAsync(
                    p,
                    outputFile);
                inputFileName = serviceIOFiles.InputFileName;
                outputFileName = serviceIOFiles.OutputFileName;

                ValidateFileName(outputFileName);

                // Return JSON metadata, not file bytes
                // Read unprotected file
                var protectedBytes = await System.IO.File.ReadAllBytesAsync(outputFileName);

                string fileBase64string = Convert.ToBase64String(protectedBytes);

                resp.StatusCode = HttpStatusCode.OK;
                resp.StatusMessage = "Success";
                resp.FileResponseContent = fileBase64string;

            }
            catch (Exception ex)
            {
                resp.StatusCode = HttpStatusCode.BadRequest;
                resp.StatusMessage = "Error :" + ex.Message;
                resp.FileResponseContent = "";
            }
            finally
            {
                CleanupFiles(inputFileName, outputFileName);
            }
            return Ok(resp);
        }

        [HttpPost("GetProtectedFileDetailsWithOwnerWithFile")]
        [RequestSizeLimit(100_000_000)]
        
        public async Task<IActionResult> GetProtectedFileDetailsWithOwnerWithFile(
            [FromForm] FileRequest p)
        {
            return await ProtectFileWithOwner(p, true);

        }
        [HttpPost("GetProtectedFileDetailsWithOwnerWithBase64File")]
        [RequestSizeLimit(100_000_000)]
        
        public async Task<IActionResult> GetProtectedFileDetailsWithOwnerWithBase64File(
            [FromBody] FileRequest p)
        {
            return await ProtectFileWithOwner(p, false);
        }

        private async Task<IActionResult> ProtectFileWithOwner(
            FileRequest p, bool isFile)
        {
            var resp = new FileResponse();
            string inputFileName = null;
            string outputFileName = null;
            try
            {
                ValidateRequest(p, isFile, true);

                var ext = Path.GetExtension(p.FileName); // returns .exe
                var fname = Path.GetFileNameWithoutExtension(p.FileName);
                var outputFile = fname + ext;

                var serviceIOFiles = await _fileService.ProtectFileWithOwnerAsync(
                    p,
                    outputFile);
                inputFileName = serviceIOFiles.InputFileName;
                outputFileName = serviceIOFiles.OutputFileName;
                // Return JSON metadata, not file bytes
                // Read unprotected file
                var protectedBytes = await System.IO.File.ReadAllBytesAsync(outputFileName);

                string fileBase64string = Convert.ToBase64String(protectedBytes);

                resp.StatusCode = HttpStatusCode.OK;
                resp.StatusMessage = "Success";
                resp.FileResponseContent = fileBase64string;

            }
            catch (Exception ex)
            {
                resp.StatusCode = HttpStatusCode.BadRequest;
                resp.StatusMessage = "Error :" + ex.Message;
                resp.FileResponseContent = "";
            }
            finally
            {
                CleanupFiles(inputFileName, outputFileName);
            }
            return Ok(resp);
        }

        [HttpPost("GetProtectedFileDetailsWithOwnerAlternateWithFile")]
        [RequestSizeLimit(100_000_000)]
        
        public async Task<IActionResult> GetProtectedFileDetailsWithOwnerAlternateWithFile(
            [FromForm] FileRequest p)
        {
            return await ProtectFileWithOwner(p, true);

        }
        [HttpPost("GetProtectedFileDetailsWithOwnerAlternateWithBase64File")]
        [RequestSizeLimit(100_000_000)]
        
        public async Task<IActionResult> GetProtectedFileDetailsWithOwnerAlternateWithBase64File(
            [FromBody] FileRequest p)
        {
            return await ProtectFileWithOwnerAlternate(p, false);
        }

        private async Task<IActionResult> ProtectFileWithOwnerAlternate(
            FileRequest p, bool isFile)
        {
            var resp = new FileResponse();
            string inputFileName = null;
            string outputFileName = null;
            try {

                ValidateRequest(p, isFile, true);

                var ext = Path.GetExtension(p.FileName); // returns .exe
                var fname = Path.GetFileNameWithoutExtension(p.FileName);
                var outputFile = fname + ext;

                p.OwnerEmailId = p.Email;
                var serviceIOFiles = await _fileService.ProtectFileWithOwnerAlternateAsync(
                    p,
                    outputFile);
                inputFileName = serviceIOFiles.InputFileName;
                outputFileName = serviceIOFiles.OutputFileName;

                ValidateFileName(outputFileName);
                // Return JSON metadata, not file bytes
                // Read unprotected file
                var protectedBytes = await System.IO.File.ReadAllBytesAsync(outputFileName);
                
                string fileBase64string = Convert.ToBase64String(protectedBytes);

                resp.StatusCode = HttpStatusCode.OK;
                resp.StatusMessage = "Success";
                resp.FileResponseContent = fileBase64string;

            }
            catch (Exception ex)
            {
                resp.StatusCode = HttpStatusCode.BadRequest;
                resp.StatusMessage = "Error :" + ex.Message;
                resp.FileResponseContent = "";
            }
            finally
            {
                CleanupFiles(inputFileName, outputFileName);
            }
            return Ok(resp);
        }

        private void ValidateRequest(FileRequest p, bool validateFile, bool validateEmail)
        {
            if (validateFile && (p.File == null || p.File.Length == 0))
                throw new Exception("file is required.");

            if (!validateFile && (p.FileBase64StringContent == null || p.FileBase64StringContent.Length == 0))
                throw new Exception("fileBase64StringContent is required.");

            if (validateEmail && (p.Email == null || p.Email.Length == 0))
                throw new Exception("Email is required.");

            if (p.FileName == null || p.FileName.Length == 0)
                throw new Exception("fileName is required.");

            if (p.FileName.Contains(".."))
                throw new Exception("fileName is invalid.");

            var fe = Path.GetExtension(p.File.FileName);
            if (_fileService.getMipSdkOptions().UnsupportedFileExtensions.Contains(fe))
            {
                throw new Exception("Unsupported file type.");
            }

            //if (IsFileNameInvalid(p.FileName))
            //{
            //    throw new Exception("fileName is invalid.");
            //}
            Console.WriteLine("-----Request--------");
            string jsonString = JsonSerializer.Serialize(p);
            Console.WriteLine(jsonString);
        }
        private void CleanupFiles(string inputFileName, string outputFileName)
        {
            try
            {
                // Cleanup
                if (!_fileService.getMipSdkOptions().RetainInputFiles &&
                    inputFileName != null && System.IO.File.Exists(inputFileName) && 
                    !inputFileName.Contains(".."))
                {
                    System.IO.File.Delete(inputFileName);
                }
                if (!_fileService.getMipSdkOptions().RetainOutputFiles &&
                    outputFileName != null && System.IO.File.Exists(outputFileName) && 
                    !outputFileName.Contains(".."))
                {
                    System.IO.File.Delete(outputFileName);
                }
            }
            catch(Exception e)
            {
                Console.WriteLine(e.StackTrace);
            }
        }
        private void ValidateFileName(string fileName)
        {

            var fn = Path.GetExtension(fileName);

            var fe = Path.GetFileNameWithoutExtension(fileName);

            if (!System.IO.File.Exists(fileName) || fileName.Contains(".."))
                throw new FileNotFoundException("File not found.", fn + fe);

            if (!fileName.StartsWith(_fileService.getMipSdkOptions().OutputFolder))
                throw new FileNotFoundException("File not found.", fn + fe);
        }

        static bool IsFileNameInvalid(string fileName)
        {
            if (string.IsNullOrWhiteSpace(fileName))
                return false;

            return FileNameRegex.IsMatch(fileName);
        }
        private static readonly Regex FileNameRegex = new Regex(
            @"^[a-zA-Z0-9 _-]+$",
            RegexOptions.IgnoreCase | RegexOptions.Compiled
        );
    }
}
