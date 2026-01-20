using DM_MIP_SA_WebApp.Models;
using DM_MIP_SA_WebApp.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder.Extensions;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;

namespace DM_MIP_SA_WebApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class FileController : ControllerBase
    {
        private readonly IFileService _fileService;

        public FileController(IFileService fileSvc)
        {
            _fileService = fileSvc;
        }

        [HttpPost("protect")]
        [RequestSizeLimit(100_000_000)]
        public async Task<IActionResult> ProtectFile(
            [FromForm] ProtectFileRequest p)
        {
            if (p.File == null || p.File.Length == 0)
                return BadRequest("File is required.");

            List<String> rightList = p.Rights.Split(",").ToList();
            foreach (var right in rightList)
            {
                RightsEnum eRights;
                if (Enum.TryParse(right, out eRights))
                {
                    Console.WriteLine($"'{right}' is a valid enum member");
                }
                else
                {
                    Console.WriteLine($"'{right}' is NOT a valid enum member.");
                    return BadRequest($"Invalid rights sepcified : {right}");
                }
            }

            var ext = Path.GetExtension(p.File.FileName); // returns .exe
            var fname = Path.GetFileNameWithoutExtension(p.File.FileName);
            var outputFile = fname + "_protected" + ext;
            
            var fileName = await _fileService.ProtectFileWithUserDefinedPermissionsAsync(
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
            return File(protectedBytes, "application/octet-stream",
                $"{outputFile}");

        }
        [HttpPost("unprotect")]
        [RequestSizeLimit(100_000_000)]
        public async Task<IActionResult> UnprotectFile(
            [FromForm] UnprotectFileRequest p)
        {
            if (p.File == null || p.File.Length == 0)
                return BadRequest("File is required.");
                        
            var ext = Path.GetExtension(p.File.FileName); // returns .exe
            var fname = Path.GetFileNameWithoutExtension(p.File.FileName);
            var outputFile = fname + "_unprotected" + ext;
            
            var fileName = await _fileService.UnprotectFileAsync(
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

        [HttpPost("additional-protect")]
        [RequestSizeLimit(100_000_000)]
        public async Task<IActionResult> AdditionalProtectFile(
            [FromForm] ProtectFileRequest p)
        {
            if (p.File == null || p.File.Length == 0)
                return BadRequest("File is required.");

            List<String> rightList = p.Rights.Split(",").ToList();
            foreach (var right in rightList)
            {
                RightsEnum eRights;
                if (Enum.TryParse(right, out eRights))
                {
                    Console.WriteLine($"'{right}' is a valid enum member");
                }
                else
                {
                    Console.WriteLine($"'{right}' is NOT a valid enum member.");
                    return BadRequest($"Invalid rights sepcified : {right}");
                }
            }

           
            var ext = Path.GetExtension(p.File.FileName); // returns .exe
            var fname = Path.GetFileNameWithoutExtension(p.File.FileName);
            var outputFile = fname + "_protected" + ext;
            
            var fileName = await _fileService.ProtectFileWithUserDefinedPermissionsAsync(
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
            return File(protectedBytes, "application/octet-stream",
                $"{outputFile}");

        }
    }
}
