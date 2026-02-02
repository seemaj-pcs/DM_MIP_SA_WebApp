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
            try
            {
                if (p.FileBase64StringContent == null || p.FileBase64StringContent.Length == 0)
                    return BadRequest("FileBase64StringContent is required.");

                List<String> rightList = p.FileAccessRightType.Split(",").ToList();

                var ext = Path.GetExtension(p.FileName); // returns .exe
                var fname = Path.GetFileNameWithoutExtension(p.FileName);
                var outputFile = fname + "_protected" + ext;

                var fileName = await _fileService.ProtectFileAsync(
                    p,
                    outputFile);

                // Return JSON metadata, not file bytes
                // Read unprotected file
                var protectedBytes = await System.IO.File.ReadAllBytesAsync(fileName);

                // Cleanup
                if (!_fileService.getMipSdkOptions().RetainOutputFiles)
                {
                    System.IO.File.Delete(fileName);
                }

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
            return Ok(resp);

        }
        [HttpPost("GetUnProtectedFileDetails")]
        [RequestSizeLimit(100_000_000)]
        public async Task<IActionResult> UnprotectFile(
            [FromBody] FileRequest p)
        {
            var resp = new FileResponse();
            
            try
            {
                if (p.FileBase64StringContent == null || p.FileBase64StringContent.Length == 0)
                    return BadRequest("FileBase64StringContent is required.");
                        
                var ext = Path.GetExtension(p.FileName); // returns .exe
                var fname = Path.GetFileNameWithoutExtension(p.FileName);
                var outputFile = fname + "_unprotected" + ext;
            
                var fileName = await _fileService.UnprotectFileAsync(
                    p,
                    outputFile);

                // Return JSON metadata, not file bytes
                // Read unprotected file
                var unprotectedBytes = await System.IO.File.ReadAllBytesAsync(fileName);

                // Cleanup
                System.IO.File.Delete(fileName);

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
            return Ok(resp);
        }

        [HttpPost("AssignAdditionalUserPermissions")]
        [RequestSizeLimit(100_000_000)]
        public async Task<IActionResult> AdditionalProtectFile(
            [FromBody] FileRequest p)
        {
            var resp = new FileResponse();
            try
            {
                if (p.FileBase64StringContent == null || p.FileBase64StringContent.Length == 0)
                    return BadRequest("FileBase64StringContent is required.");

                List<String> rightList = p.FileAccessRightType.Split(",").ToList();
                       
                var ext = Path.GetExtension(p.FileName); // returns .exe
                var fname = Path.GetFileNameWithoutExtension(p.FileName);
                var outputFile = fname + "_protected" + ext;
            
                var fileName = await _fileService.AdditionalProtectFileAsync(
                    p,
                    outputFile);

                // Return JSON metadata, not file bytes
                // Read unprotected file
                var protectedBytes = await System.IO.File.ReadAllBytesAsync(fileName);

                // Cleanup
                if (!_fileService.getMipSdkOptions().RetainOutputFiles)
                {
                    System.IO.File.Delete(fileName);
                }
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
            return Ok(resp);
        }
    
        [HttpPost("GetProtectedFileDetailsWithOwner")]
        [RequestSizeLimit(100_000_000)]
        public async Task<IActionResult> ProtectFileWithOwner(
            [FromForm] FileRequest p)
        {
            var resp = new FileResponse();
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

                var fileName = await _fileService.ProtectFileWithOwnerAsync(
                    p,
                    outputFile);

                // Return JSON metadata, not file bytes
                // Read unprotected file
                var protectedBytes = await System.IO.File.ReadAllBytesAsync(fileName);
                // Cleanup
                System.IO.File.Delete(fileName);

                return File(protectedBytes, "application/octet-stream",
                    $"{outputFile}");
            }
            catch (Exception ex)
            {
                resp.StatusCode = HttpStatusCode.BadRequest;
                resp.StatusMessage = "Error :" + ex.Message;
                resp.FileResponseContent = "";
            }
            return Ok(resp);
}
        [HttpPost("GetProtectedFileDetailsWithOwnerAlternate")]
        [RequestSizeLimit(100_000_000)]
        public async Task<IActionResult> ProtectFileWithOwnerAlternate(
            [FromForm] FileRequest p)
        {
            var resp = new FileResponse();
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
            var fileName = await _fileService.ProtectFileWithOwnerAlternateAsync(
                p,
                outputFile);

            // Return JSON metadata, not file bytes
            // Read unprotected file
            var protectedBytes = await System.IO.File.ReadAllBytesAsync(fileName);
            // Cleanup
            System.IO.File.Delete(fileName);

            return File(protectedBytes, "application/octet-stream",
                $"{outputFile}");

            }
            catch (Exception ex)
            {
                resp.StatusCode = HttpStatusCode.BadRequest;
                resp.StatusMessage = "Error :" + ex.Message;
                resp.FileResponseContent = "";
            }
            return Ok(resp);
        }
    }
}
