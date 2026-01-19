using DM_MIP_SA_WebApp.Models;
using Microsoft.Extensions.Options;
using Microsoft.Graph.Models;
using Microsoft.InformationProtection;
using Microsoft.InformationProtection.File;
using Microsoft.InformationProtection.Protection;
using System.Security.Claims;

namespace DM_MIP_SA_WebApp.Services
{
    public interface IFileService_Backup
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
    }

    public class FileService_Backup : IFileService_Backup
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

        public FileService_Backup(
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
            
            _logger.LogInformation("Starting file protection for: {FileName}", definition.File.FileName);

            var inputFolder = _mipOptions.InputFolder;

            string filePath = CreateFile(definition.File, inputFolder, definition.File.FileName).Result;

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
                new AuthDelegateImpl(_authService),
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

            if (labelIDToApply == null) {
                throw new Exception("Unable to find label to apply.");
            }

            var emailList = definition.Email.Split(",").ToList();
            var rights = definition.Rights.Split(",").ToList();

            var userRightsList = new List<UserRights>();
            userRightsList.Add(new UserRights(
                new List<string> { definition.OwnerEmail },
                new List<string> { Rights.Owner, Rights.Extract }));

            foreach ( var email in emailList )
            {
                userRightsList.Add(new UserRights(new List<string> { email }, rights));
            }
            
            _logger.LogInformation("Added permissions for {Email}: {Rights}", definition.Email, string.Join(", ", rights));
            _logger.LogInformation("Added owner permissions for caller: {CallerEmail}", definition.OwnerEmail);

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
                        true)
                    .ConfigureAwait(false);

                var protection = handler.Protection;
                //if (protection != null)
                //{
                //    _logger.LogInformation($"protection.IssuedTo ------ {protection.IssuedTo}");
                //    if (!protection.IsIssuedToOwner)
                //    {
                //        throw new InvalidOperationException("Owner mismatch. Cannot complete operation");
                //    }
                //}
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

                //--------Apply label------

                //Apply protection
                var descriptor = new ProtectionDescriptor(userRightsList);
                handler.SetProtection(descriptor, new ProtectionSettings());

                var protectionSettings = new ProtectionSettings()
                {
                    DelegatedUserEmail = string.IsNullOrWhiteSpace(definition.OwnerEmail) ? _mipOptions.ServiceAccountEmail : definition.OwnerEmail
                };
                handler.SetLabel(labelIDToApply, new LabelingOptions(), protectionSettings);
                await handler.CommitAsync(outfilePath).ConfigureAwait(false);

                _logger.LogInformation("Committing protected file");

                await handler.CommitAsync(outfilePath).ConfigureAwait(false);

                var fi = new FileInfo(outfilePath);

                _logger.LogInformation("File protection completed successfully - Output: {OutputPath}, Size: {Size} bytes", outfilePath, fi.Length);

                if (definition.SendEmail)
                {
                    await _emailService.sendEmail(_azureAdOptions,
                            _emailOptions, outfilePath, definition.Email);
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
                if (definition.RetainOutputFiles != null && !definition.RetainOutputFiles.Value) { 
                    try { if (File.Exists(filePath)) File.Delete(filePath); } catch { }
                }
            }
        }


        public async Task<string> UnprotectFileAsync(
            UnprotectFileRequest definition,
            string outFileName)
        {
            if (string.IsNullOrWhiteSpace(_mipOptions.UnprotectedFileFolder))
                throw new ArgumentException("OutputFolderPath is required in protectionDefinition.", nameof(definition));

            _logger.LogInformation("Starting file protection for: {FileName}", definition.File.FileName);

            var inputFolder = _mipOptions.InputFolder;

            string filePath = CreateFile(definition.File, inputFolder, definition.File.FileName).Result;

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

            
            var identityId = $"{_mipOptions.ServiceAccountEmail}-webapi";

            _logger.LogInformation("Creating file engine for identity: {IdentityId}", identityId);

            var fileEngineSettings = new FileEngineSettings(identityId, authDelegate, string.Empty, "en-us")
            {
                Identity = new Microsoft.InformationProtection.Identity(identityId)
            };

            var fileEngine = await fileProfile.AddEngineAsync(fileEngineSettings)
                                              .ConfigureAwait(false);

            var protectionEngineSettings = new ProtectionEngineSettings(identityId, authDelegate, string.Empty, "en-us")
            {
                Identity = new Microsoft.InformationProtection.Identity(identityId)
            };

            _ = await protectionProfile.AddEngineAsync(protectionEngineSettings)
                                       .ConfigureAwait(false);

            var outputFolder = _mipOptions.UnprotectedFileFolder;
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

                handler.RemoveProtection();

                _logger.LogInformation("Committing unprotected file");

                await handler.CommitAsync(outfilePath).ConfigureAwait(false);

                var fi = new FileInfo(outfilePath);

                _logger.LogInformation("File unprotection completed successfully - Output: {OutputPath}, Size: {Size} bytes", outfilePath, fi.Length);

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
                if (definition.RetainOutputFiles != null && !definition.RetainOutputFiles.Value)
                {
                    try { if (File.Exists(filePath)) File.Delete(filePath); } catch { }
                }
            }
        }


        public async Task<string> AdditionalProtectFileWithUserDefinedPermissionsAsync(
            ProtectFileRequest definition,
            string outFileName)
        {
            if (string.IsNullOrWhiteSpace(_mipOptions.InputFolder))
                throw new ArgumentException("InputFolder is required in protectionDefinition.", nameof(definition));

            if (string.IsNullOrWhiteSpace(_mipOptions.ProtectedFileFolder))
                throw new ArgumentException("OutputFolder is required in protectionDefinition.", nameof(definition));

            _logger.LogInformation("Starting file protection for: {FileName}", definition.File.FileName);

            var inputFolder = _mipOptions.InputFolder;

            string filePath = CreateFile(definition.File, inputFolder, definition.File.FileName).Result;

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
                new AuthDelegateImpl(_authService),
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

            var emailList = definition.Email.Split(",").ToList();
            var rights = definition.Rights.Split(",").ToList();

            var userRightsList = new List<UserRights>();
            userRightsList.Add(new UserRights(
                new List<string> { definition.OwnerEmail },
                new List<string> { Rights.Owner, Rights.Extract }));

            foreach (var email in emailList)
            {
                userRightsList.Add(new UserRights(new List<string> { email }, rights));
            }

            _logger.LogInformation("Added permissions for {Email}: {Rights}", definition.Email, string.Join(", ", rights));
            _logger.LogInformation("Added owner permissions for caller: {CallerEmail}", definition.OwnerEmail);
            
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

                var protection = handler.Protection;
                //if (protection != null)
                //{
                //    if (!protection.IsIssuedToOwner)
                //    {
                //        throw new InvalidOperationException("Owner mismatch. Cannot complete operation");
                //    }
                //}

                if (protection != null && protection.ProtectionDescriptor?.UserRights != null)
                {
                    foreach (var userRight in protection.ProtectionDescriptor.UserRights)
                    {
                        userRightsList.Add(userRight);
                    }
                }

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

                //--------Apply label------

                //Apply protection
                var descriptor = new ProtectionDescriptor(userRightsList);
                handler.SetProtection(descriptor, new ProtectionSettings());

                var protectionSettings = new ProtectionSettings()
                {
                    DelegatedUserEmail = string.IsNullOrWhiteSpace(definition.OwnerEmail) ? _mipOptions.ServiceAccountEmail : definition.OwnerEmail
                };
                handler.SetLabel(labelIDToApply, new LabelingOptions(), protectionSettings);
                await handler.CommitAsync(outfilePath).ConfigureAwait(false);

                _logger.LogInformation("Committing protected file");

                var fi = new FileInfo(outfilePath);

                _logger.LogInformation("File protection completed successfully - Output: {OutputPath}, Size: {Size} bytes", outfilePath, fi.Length);

                if (definition.SendEmail)
                {
                    await _emailService.sendEmail(_azureAdOptions,
                            _emailOptions, outfilePath, definition.Email);
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
                if (definition.RetainOutputFiles != null && !definition.RetainOutputFiles.Value)
                {
                    try { if (File.Exists(filePath)) File.Delete(filePath); } catch { }
                }
            }
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