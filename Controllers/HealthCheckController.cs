using Microsoft.AspNetCore.Mvc;

namespace DM_MIP_SA_WebApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class HealthCheckController : ControllerBase
    {
        /// <summary>
        /// Health check endpoint to verify API is running.
        /// </summary>
        /// <returns>Simple health status response.</returns>
        [HttpGet("status")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public IActionResult HealthCheck()
        {
            var response = new
            {
                status = "healthy",
                timestamp = DateTime.UtcNow,
                service = "DM_MIP_SDK_APP"
            };

            return Ok(response);
        }
    }
}
