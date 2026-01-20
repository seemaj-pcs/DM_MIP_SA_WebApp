using DM_MIP_SA_WebApp.Models;
using Microsoft.Extensions.Options;
using Microsoft.Graph.Models;
using Microsoft.InformationProtection;
using Microsoft.InformationProtection.File;
using Microsoft.InformationProtection.Protection;
using System.Security.Claims;

namespace DM_MIP_SA_WebApp.Services
{
    public interface IFileService
    {
        Task<string> ProtectFileWithUserDefinedPermissionsAsync(
            ProtectFileRequest definition,
            string outFileName);

        Task<string> UnprotectFileAsync(
           UnprotectFileRequest definition,
           string outFileName);

        Task<string> AdditionalProtectFileWithUserDefinedPermissionsAsync(
           ProtectFileRequest definition,
           string outFileName);

        public MipSdkOptions getMipSdkOptions();
    }

    public class FileService : IFileService
    {
        private readonly MipSdkOptions _mipOptions;
        private readonly AuthService _authService;
        private readonly EmailOptions _emailOptions;
        private readonly EmailService _emailService;
        private readonly AzureAdOptions _azureAdOptions;
        private readonly ILogger<FileService> _logger;
        private readonly ILoggerFactory _loggerFactory;
        private static bool _mipInitialized;
        private static readonly object _initLock = new();

        public FileService(
            IOptions<MipSdkOptions> mipOptions,
            AuthService authService,
            IOptions<EmailOptions> emailOptions,
            EmailService emailService,
            IOptions<AzureAdOptions> azureAdOptions,
            ILogger<FileService> logger,
            ILoggerFactory loggerFactory)
        {
            _mipOptions = mipOptions.Value;
            _authService = authService;
            _emailOptions = emailOptions.Value;
            _emailService = emailService;
            _azureAdOptions = azureAdOptions.Value;
            _logger = logger;
            _loggerFactory = loggerFactory;
            EnsureMipInitialized();
        }

        private void EnsureMipInitialized()
        {
            if (_mipInitialized) return;

            lock (_initLock)
            {
                if (_mipInitialized) return;

                // Match console app behaviour: initialize File SDK
                MIP.Initialize(MipComponent.File);
                _mipInitialized = true;
                _logger.LogInformation("MIP SDK initialized");
            }
        }

        public async Task<string> ProtectFileWithUserDefinedPermissionsAsync(
            ProtectFileRequest definition,
            string outFileName)
        {
            if (string.IsNullOrWhiteSpace(_mipOptions.InputFolder))
                throw new ArgumentException("InputFolder is required in protectionDefinition.", nameof(definition));

            if (string.IsNullOrWhiteSpace(_mipOptions.ProtectedFileFolder))
                throw new ArgumentException("OutputFolder is required in protectionDefinition.", nameof(definition));

            return await ApplyLabelAndProtectionAsync(
            definition.File, definition.Email, definition.Rights, 
            true, true, false, outFileName);
        }


        public async Task<string> UnprotectFileAsync(
            UnprotectFileRequest definition,
            string outFileName)
        {
            if (string.IsNullOrWhiteSpace(_mipOptions.UnprotectedFileFolder))
                throw new ArgumentException("OutputFolderPath is required in protectionDefinition.", nameof(definition));

            return await ApplyLabelAndProtectionAsync(
            definition.File, "", "", 
            false, true, false, outFileName);
        }

        public async Task<string> AdditionalProtectFileWithUserDefinedPermissionsAsync(
            ProtectFileRequest definition,
            string outFileName)
        {
            if (string.IsNullOrWhiteSpace(_mipOptions.InputFolder))
                throw new ArgumentException("InputFolder is required in protectionDefinition.", nameof(definition));

            if (string.IsNullOrWhiteSpace(_mipOptions.ProtectedFileFolder))
                throw new ArgumentException("OutputFolder is required in protectionDefinition.", nameof(definition));

            return await ApplyLabelAndProtectionAsync(
            definition.File, definition.Email, definition.Rights, 
            true, true, true, outFileName);
        }
        public async Task<string> ApplyLabelAndProtectionAsync(
            IFormFile req_inFile, string req_email, string req_rights, 
            bool applyLabelAndProtection, bool removeLabelAndProtected, bool applyAdditionalProtection,
            string outFileName)
        {
            _logger.LogInformation("Starting file protection for: {FileName}", req_inFile.FileName);

            var inputFolder = _mipOptions.InputFolder;

            string filePath = CreateFile(req_inFile, inputFolder, req_inFile.FileName).Result;

            _logger.LogInformation($"filePath -------------- {filePath}");

            var appInfo = new ApplicationInfo
            {
                ApplicationId = _mipOptions.AppId,
                ApplicationName = _mipOptions.AppName,
                ApplicationVersion = _mipOptions.AppVersion
            };

            // Auth delegate that uses OBO via AuthService
            var authDelegate = new AuthDelegateImpl(_authService);

            var mipConfig = new MipConfiguration(
                appInfo,
                _mipOptions.CachePath,
                Microsoft.InformationProtection.LogLevel.Trace,
                false,
                CacheStorageType.OnDiskEncrypted);

            var mipContext = MIP.CreateMipContext(mipConfig);

            var fileProfileSettings = new FileProfileSettings(
                mipContext,
                CacheStorageType.OnDiskEncrypted,
                new ConsentDelegateImpl());

            var fileProfile = await MIP.LoadFileProfileAsync(fileProfileSettings)
                                       .ConfigureAwait(false);

            var protectionProfileSettings = new ProtectionProfileSettings(
                mipContext,
                CacheStorageType.InMemory,
                new ConsentDelegateImpl());

            var protectionProfile = await MIP.LoadProtectionProfileAsync(protectionProfileSettings)
                                             .ConfigureAwait(false);

            var serviceAccountEmail = _mipOptions.ServiceAccountEmail;

            Console.WriteLine($"---serviceAccountEmail -- {serviceAccountEmail}");
            var fileEngineSettings = new FileEngineSettings(
                _mipOptions.EngineId,
                authDelegate,
                "",
                "en-US")
            {
                Identity = new Microsoft.InformationProtection.Identity(serviceAccountEmail)
            };

            var identityId = $"{_mipOptions.ServiceAccountEmail}-webapi";

            var fileEngine = await fileProfile.AddEngineAsync(fileEngineSettings)
                                              .ConfigureAwait(false);

            var labels = fileEngine.SensitivityLabels;
            Label labelIDToApply = null;
            foreach (var label in labels)
            {
                Console.WriteLine($"labelID - {label.Id}");
                Console.WriteLine($"labelName - {label.Name}");
                if (label.Name == _mipOptions.LabelToApply)
                {
                    labelIDToApply = label;
                    break;
                }
            }
            // Build UDP (UserRights) from definition

            var emailList = req_email.Split(",").ToList();
            var rights = req_rights.Split(",").ToList();

            var userRightsList = new List<UserRights>();
            userRightsList.Add(new UserRights(
                new List<string> { _mipOptions.ServiceAccountEmail },
                new List<string> { Rights.Owner, Rights.Extract }));

            foreach (var email in emailList)
            {
                userRightsList.Add(new UserRights(new List<string> { email }, rights));
            }

            _logger.LogInformation("Added permissions for {Email}: {Rights}", req_email, string.Join(", ", rights));
            _logger.LogInformation("Added owner permissions for caller: {CallerEmail}", _mipOptions.ServiceAccountEmail);
            
            if (userRightsList.Count == 0)
                throw new InvalidOperationException("No valid user permissions were provided.");

            var outputFolder = _mipOptions.ProtectedFileFolder;
            if (!Directory.Exists(outputFolder))
            {
                Directory.CreateDirectory(outputFolder);
            }
            var outfilePath = Path.Combine(outputFolder, outFileName);

            try
            {
                _logger.LogInformation("Created handler for temporary file");


                // Create handler and set protection
                var handler = await fileEngine.CreateFileHandlerAsync(
                        filePath,
                        filePath,
                        false)
                    .ConfigureAwait(false);

                if (applyAdditionalProtection) { 
                    var protection = handler.Protection;
                    
                    if (protection != null && protection.ProtectionDescriptor?.UserRights != null)
                    {
                        foreach (var userRight in protection.ProtectionDescriptor.UserRights)
                        {
                            userRightsList.Add(userRight);
                        }
                    }
                }

                if (removeLabelAndProtected)
                {
                    //Remove Label---------------------
                    var removeLabelingOptions = new LabelingOptions()
                    {
                        AssignmentMethod = AssignmentMethod.Privileged, // Indicates a manual/privileged operation
                        IsDowngradeJustified = true,
                        JustificationMessage = "Removing label via MIP SDK application"
                    };


                    // 2. Check and remove protection if it exists
                    if (handler.Protection != null)
                    {
                        handler.RemoveProtection();
                    }

                    // 3. Delete the label from the file
                    handler.DeleteLabel(removeLabelingOptions);
                    await handler.CommitAsync(outfilePath).ConfigureAwait(false);

                    _logger.LogInformation("Committing unprotected file");
                }
                //--------Apply label------
                if (applyLabelAndProtection)
                {
                    //Apply protection
                    var descriptor = new ProtectionDescriptor(userRightsList);
                    handler.SetProtection(descriptor, new ProtectionSettings());

                    var protectionSettings = new ProtectionSettings()
                    {
                        DelegatedUserEmail = _mipOptions.ServiceAccountEmail
                    };
                    handler.SetLabel(labelIDToApply, new LabelingOptions(), protectionSettings);
                    await handler.CommitAsync(outfilePath).ConfigureAwait(false);

                    _logger.LogInformation("Committing protected file");
                }
                var fi = new FileInfo(outfilePath);

                _logger.LogInformation("File protection completed successfully - Output: {OutputPath}, Size: {Size} bytes", outfilePath, fi.Length);


                if (_mipOptions.SendEmail)
                {
                    var subject = "default";
                    var action = "default";
                    if (applyAdditionalProtection)
                    {
                        subject = "Additional Permissions Applied";
                        action = "Additionally Protected";
                    }
                    else if (removeLabelAndProtected && !applyAdditionalProtection && !applyLabelAndProtection)
                    {
                        subject = "Protection Removed";
                        action = "Unprotected";
                    }
                    else
                    {
                        subject = "Protection Applied";
                        action = "Protected";
                    }
                    await _emailService.sendEmail(_azureAdOptions,
                            _mipOptions, _emailOptions, outfilePath, req_email, subject, action);
                }

                return outfilePath;
            }
            finally
            {
                try
                {
                    fileEngine = null;
                    fileProfile = null;
                    mipContext.ShutDown();
                    mipContext = null;
                }
                catch { }
                
            }
        }
        public MipSdkOptions getMipSdkOptions()
        {
            return _mipOptions;
        }
        private async Task<string> CreateFile(IFormFile file, string dir, String inFileName)
        {
            if (!Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }

            var tempPath = Path.Combine(dir,
                $"{inFileName}");

            if (File.Exists(tempPath))
            {
                tempPath = Path.Combine(dir,
                $"{Guid.NewGuid()}_{inFileName}");
            }
            // Save temp file
            
            using (var stream = new FileStream(tempPath, FileMode.Create))
            {
                await file.CopyToAsync(stream);
            }
            return tempPath;
        }
    }
}