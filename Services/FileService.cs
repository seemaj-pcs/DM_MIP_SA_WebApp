using Azure.Core;
using DM_MIP_SA_WebApp.Models;
using Microsoft.Extensions.Options;
using Microsoft.Graph.Models;
using Microsoft.Graph.Models.Security;
using Microsoft.InformationProtection;
using Microsoft.InformationProtection.File;
using Microsoft.InformationProtection.Protection;
using System.Security.Claims;

namespace DM_MIP_SA_WebApp.Services
{
    public class ServiceIOFiles
    {
        public string InputFileName { get; set; }
        public string OutputFileName { get; set; }

    }
    public interface IFileService
    {
        Task<ServiceIOFiles> ProtectFileAsync(
            FileRequest definition,
            string outFileName);

        Task<ServiceIOFiles> UnprotectFileAsync(
           FileRequest definition,
           string outFileName);

        Task<ServiceIOFiles> AdditionalProtectFileAsync(
           FileRequest definition,
           string outFileName);

        Task<ServiceIOFiles> ProtectFileWithOwnerAsync(
           FileRequest definition,
           string outFileName);

        Task<ServiceIOFiles> ProtectFileWithOwnerAlternateAsync(
          FileRequest definition,
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

        public async Task<ServiceIOFiles> ProtectFileAsync(
            FileRequest definition,
            string outFileName)
        {
           return await ApplyLabelAndProtectionAsync(
            definition, false,
            true, true, false, outFileName);
        }


        public async Task<ServiceIOFiles> UnprotectFileAsync(
            FileRequest definition,
            string outFileName)
        {
            return await ApplyLabelAndProtectionAsync(
            definition, false,
            false, true, false, outFileName);
        }

        public async Task<ServiceIOFiles> AdditionalProtectFileAsync(
            FileRequest definition,
            string outFileName)
        {
            return await ApplyLabelAndProtectionAsync(
            definition, false,
            true, true, true, outFileName);
        }
        public async Task<ServiceIOFiles> ProtectFileWithOwnerAsync(
           FileRequest definition,
           string outFileName)
        {
            return await ApplyLabelAndProtectionAsync(
             definition, true,
             true, true, true, outFileName);
        }
        public async Task<ServiceIOFiles> ProtectFileWithOwnerAlternateAsync(
           FileRequest definition,
           string outFileName)
        {
            return await ApplyLabelAndProtectionAsync(
             definition, true,
             true, true, true, outFileName);
        }

        public async Task<ServiceIOFiles> ApplyLabelAndProtectionAsync(
            FileRequest definition, bool overrideOwner, bool applyLabelAndProtection, bool removeLabelAndProtected, bool applyAdditionalProtection,
            string outFileName)
        {
            _logger.LogInformation("Starting file protection for: {FileName}", definition.FileName);

            var inputFolder = _mipOptions.InputFolder;
            string inputFilePath = null;
            if (definition.File != null)
            {
                inputFilePath = await CreateFileWithIFormFile(definition.File, inputFolder, definition.File.FileName);
            }
            else
            {
                inputFilePath = CreateFileWithFileContents(definition.FileName, definition.FileBase64StringContent, inputFolder).Result;
            }
            var ext = Path.GetExtension(inputFilePath); // returns .exe
            var fname = Path.GetFileNameWithoutExtension(inputFilePath);
            _logger.LogInformation($"File Extension ------------------ {ext}");
            if (_mipOptions.UnsupportedFileExtensions.Contains(ext))
            {
                throw new Exception("Unsupported File format");
            }
            _logger.LogInformation($"inputFilePath -------------- {inputFilePath}");

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
            _logger.LogInformation($"Adding definition.OwnerEmailId -------- {definition.OwnerEmailId}");

            var userRightsList = new List<UserRights>();
            string ownerEmail = _mipOptions.ServiceAccountEmail;

            if (definition.OwnerEmailId != null && definition.OwnerEmailId.Trim().Length > 0)
            {
                ownerEmail = definition.OwnerEmailId;
            }

            _logger.LogInformation($"Adding OWNER -------- {ownerEmail}");
            userRightsList.Add(new UserRights(
                new List<string> { ownerEmail },
                new List<string> { Rights.Owner, Rights.Extract }));

            // Build UDP (UserRights) from definition
            if (definition.FileAccessRightType != null && definition.FileAccessRightType.Length > 0)
            {
                var emailList = definition.Email.Split(",").ToList();
                //var rights = req_rights.Split(",").ToList();
                var rights2 = definition.FileAccessRightType.Split(",").ToList();
                var rights = new List<string>();
                foreach (var r in rights2)
                {
                    //switch (r)
                    //{
                    //    case "1":
                    //        rights.Add(Rights.View);
                    //        break;
                    //    default:
                    //        break;
                    //}
                    string s = "";
                    _mipOptions.FileRights.TryGetValue(r, out s);
                    _logger.LogInformation($"Added permissions for {s}");
                    rights.Add(s);
                }


                foreach (var email in emailList)
                {
                    userRightsList.Add(new UserRights(new List<string> { email }, rights));
                }

                _logger.LogInformation("Added permissions for {Email}: {Rights}", definition.Email, string.Join(", ", rights));
                _logger.LogInformation("Added owner permissions for caller: {CallerEmail}", _mipOptions.ServiceAccountEmail);
            }
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
                        inputFilePath,
                        inputFilePath,
                        false)
                    .ConfigureAwait(false);

                if (applyAdditionalProtection)
                {
                    _logger.LogInformation($"Adding Protection -----");

                    var protection = handler.Protection;

                    if (protection != null && protection.ProtectionDescriptor?.UserRights != null)
                    {
                        foreach (var userRight in protection.ProtectionDescriptor.UserRights)
                        {
                            var users = userRight.Users.ToList();
                            var rs = new List<string>();
                            
                            foreach (var r in userRight.Rights)
                            {
                                if (overrideOwner && r.Equals("OWNER"))
                                {
                                    continue;
                                }
                                rs.Add(r);
                            }
                           _logger.LogInformation($"Adding -----Users- {string.Join(", ", users)} -Rights--- {string.Join(", ", rs)}");
                            userRightsList.Add(new UserRights(users, rs));
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
                    foreach (var ur in userRightsList)
                    {
                        _logger.LogInformation($"Dumping =========== Users- {string.Join(", ", ur.Users)} -Rights--- {string.Join(", ", ur.Rights)}");
                    }

                    if (userRightsList.Count == 0)
                        throw new InvalidOperationException("No valid user permissions were provided.");

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
                            _mipOptions, _emailOptions, outfilePath, definition.Email, subject, action);
                }
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
            ServiceIOFiles x = new ServiceIOFiles
            {
                InputFileName = inputFilePath,
                OutputFileName = outfilePath
            };
            return x;
        }
        public MipSdkOptions getMipSdkOptions()
        {
            return _mipOptions;
        }

        private async Task<string> CreateFileWithIFormFile(IFormFile file, string dir, String inFileName)
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
        private async Task<string> CreateFileWithFileContents(string fileName, string fileBase64String, string dir)
        {
            if (!Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }

            var tempPath = Path.Combine(dir,
                $"{fileName}");

            if (File.Exists(tempPath))
            {
                tempPath = Path.Combine(dir,
                $"{Guid.NewGuid()}_{fileName}");
            }
            // Save temp file
            // Convert the Base64 string to a byte array
            byte[] fileBytes = Convert.FromBase64String(fileBase64String);

            // Write the byte array to the specified file path
            File.WriteAllBytes(tempPath, fileBytes);

            return tempPath;
        }
    }

}