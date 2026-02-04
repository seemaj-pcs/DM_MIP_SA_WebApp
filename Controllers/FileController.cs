using DM_MIP_SA_WebApp.Models;
using DM_MIP_SA_WebApp.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder.Extensions;
using Microsoft.AspNetCore.Mvc;
using System.Net;
using System.Text.Json;

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

        [HttpPost("GetProtectedFileDetails")]
        [RequestSizeLimit(100_000_000)]
        public async Task<IActionResult> ProtectFile(
            [FromBody] FileRequest p)
        {
            var resp = new FileResponse();
            string inputFileName = null;
            string outputFileName = null;
            try
            {
                if (p.FileName == null || p.FileName.Length == 0)
                    return BadRequest("fileName is required.");

                if (p.FileBase64StringContent == null || p.FileBase64StringContent.Length == 0)
                    return BadRequest("fileBase64StringContent is required.");

                if (p.FileAccessRightType == null || p.FileAccessRightType.Length == 0)
                    return BadRequest("fileAccessRightType is required.");

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
                resp.StatusCode = HttpStatusCode.BadRequest;
                resp.StatusMessage = "Error :" + ex.Message;
                resp.FileResponseContent = "";
            }
            finally
            {
                // Cleanup
                if (!_fileService.getMipSdkOptions().RetainInputFiles &&
                    inputFileName != null && System.IO.File.Exists(inputFileName))
                {
                    System.IO.File.Delete(inputFileName);
                }
                if (!_fileService.getMipSdkOptions().RetainOutputFiles &&
                    outputFileName != null && System.IO.File.Exists(outputFileName))
                {
                    System.IO.File.Delete(outputFileName);
                }

            }
            return Ok(resp);

        }
        [HttpPost("GetUnProtectedFileDetails")]
        [RequestSizeLimit(100_000_000)]
        public async Task<IActionResult> UnprotectFile(
            [FromBody] FileRequest p)
        {
            var resp = new FileResponse();
            string inputFileName = null;
            string outputFileName = null;
            try
            {
                if (p.FileBase64StringContent == null || p.FileBase64StringContent.Length == 0)
                    return BadRequest("fileBase64StringContent is required.");

                if (p.FileName == null || p.FileName.Length == 0)
                    return BadRequest("fileName is required.");

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
                // Cleanup
                if (!_fileService.getMipSdkOptions().RetainInputFiles &&
                    inputFileName != null && System.IO.File.Exists(inputFileName))
                {
                    System.IO.File.Delete(inputFileName);
                }
                if (!_fileService.getMipSdkOptions().RetainOutputFiles &&
                    outputFileName != null && System.IO.File.Exists(outputFileName))
                {
                    System.IO.File.Delete(outputFileName);
                }

            }
            return Ok(resp);
        }

        [HttpPost("AssignAdditionalUserPermissions")]
        [RequestSizeLimit(100_000_000)]
        public async Task<IActionResult> AdditionalProtectFile(
            [FromBody] FileRequest p)
        {
            var resp = new FileResponse();
            string inputFileName = null;
            string outputFileName = null;
            try
            {
                if (p.FileBase64StringContent == null || p.FileBase64StringContent.Length == 0)
                    return BadRequest("fileBase64StringContent is required.");

                if (p.FileName == null || p.FileName.Length == 0)
                    return BadRequest("fileName is required.");

                if (p.FileAccessRightType == null || p.FileAccessRightType.Length == 0)
                    return BadRequest("fileAccessRightType is required.");

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
                // Cleanup
                if (!_fileService.getMipSdkOptions().RetainInputFiles &&
                    inputFileName != null && System.IO.File.Exists(inputFileName))
                {
                    System.IO.File.Delete(inputFileName);
                }
                if (!_fileService.getMipSdkOptions().RetainOutputFiles &&
                    outputFileName != null && System.IO.File.Exists(outputFileName))
                {
                    System.IO.File.Delete(outputFileName);
                }

            }
            return Ok(resp);
        }
    
        [HttpPost("GetProtectedFileDetailsWithOwner")]
        [RequestSizeLimit(100_000_000)]
        public async Task<IActionResult> ProtectFileWithOwner(
            [FromForm] FileRequest p)
        {
            var resp = new FileResponse();
            string inputFileName = null;
            string outputFileName = null;
            try
            {
                if (p.File == null || p.File.Length == 0)
                    return BadRequest("File is required.");

                if (p.OwnerEmailId == null || p.OwnerEmailId.Length == 0)
                    return BadRequest("OwnerEmailId is required.");

                if (p.FileName == null || p.FileName.Length == 0)
                    return BadRequest("FileName is required.");
               
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
                
                return File(protectedBytes, "application/octet-stream",
                    $"{outputFile}");
            }
            catch (Exception ex)
            {
                resp.StatusCode = HttpStatusCode.BadRequest;
                resp.StatusMessage = "Error :" + ex.Message;
                resp.FileResponseContent = "";
            }
            finally
            {
                // Cleanup
                if (!_fileService.getMipSdkOptions().RetainInputFiles &&
                    inputFileName != null && System.IO.File.Exists(inputFileName))
                {
                    System.IO.File.Delete(inputFileName);
                }
                if (!_fileService.getMipSdkOptions().RetainOutputFiles &&
                    outputFileName != null && System.IO.File.Exists(outputFileName))
                {
                    System.IO.File.Delete(outputFileName);
                }

            }
            return Ok(resp);
}
        [HttpPost("GetProtectedFileDetailsWithOwnerAlternate")]
        [RequestSizeLimit(100_000_000)]
        public async Task<IActionResult> ProtectFileWithOwnerAlternate(
            [FromForm] FileRequest p)
        {
            var resp = new FileResponse();
            string inputFileName = null;
            string outputFileName = null;
            try { 
            if (p.File == null || p.File.Length == 0)
                return BadRequest("File is required.");

            if (p.Email == null || p.Email.Length == 0)
                return BadRequest("Email is required.");

            if (p.FileName == null || p.FileName.Length == 0)
                return BadRequest("FileName is required.");

            
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
            
            return File(protectedBytes, "application/octet-stream",
                $"{outputFile}");

            }
            catch (Exception ex)
            {
                resp.StatusCode = HttpStatusCode.BadRequest;
                resp.StatusMessage = "Error :" + ex.Message;
                resp.FileResponseContent = "";
            }
            finally
            {
                // Cleanup
                if (!_fileService.getMipSdkOptions().RetainInputFiles &&
                    inputFileName != null && System.IO.File.Exists(inputFileName))
                {
                    System.IO.File.Delete(inputFileName);
                }
                if (!_fileService.getMipSdkOptions().RetainOutputFiles &&
                    outputFileName != null && System.IO.File.Exists(outputFileName))
                {
                    System.IO.File.Delete(outputFileName);
                }

            }
            return Ok(resp);
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

    }
}
