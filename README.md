#
# Steps to setting up the project on local machine
#
 1. Install Microsoft Visual Studio 2026 Community version from
https://visualstudio.microsoft.com/vs/community/

2.	Launch a command prompt and validate if dotnet command works well.

3.	Clone/download the project code from GITLAB and extract the same to say d:\FileProtection folder.

4.	Goto D:\FileFolder and run the following commands:
  1. dotnet add package Azure.Core
  2. dotnet add package Azure.Identity
  3. dotnet add package Microsoft.AspNetCore.OpenApi
  4. dotnet add package Microsoft.Graph
  5. dotnet add package Microsoft.Identity.Client
  6. dotnet add package Microsoft.Identity.Web
  7. dotnet add package Microsoft.InformationProtection.File
   This should download all dependencies.

5.	Click on run to start the server.
 
6.	This will build the project and start the server.

7.	Set up postman and import the attached collection into Postman.
    
8.	Test all APIs. Pick the file to encrypt and validate the same.

#
# Deploying code to server
#
1. Install .NET 1.0 runtime on the machine from 
   https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/runtime-aspnetcore-10.0.1-windows-host…
2.	Install the ASP Core package from
   https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/runtime-aspnetcore-10.0.1-windows-hosting-bundle-installer
3. Publish the ASP.NET Core Web API
	Using the .NET CLI is the standard way to prepare the application for deployment. 
	Open a terminal (command prompt or PowerShell) and navigate to your project directory.
	Run the following command to publish the API in Release mode:
	dotnet
	dotnet publish -c Release -o C:\FileProtection
	Replace C:\FileProtection with your desired output location. 
2. Configure the Physical Folder 
	Create a folder on the server (e.g., C:\inetpub\wwwroot\MyApi).
	Copy the contents from the C:\PublishPath folder created in Step 1 into this new folder.
	Permissions: Ensure the folder has read/execute permissions. Right-click the folder > Properties > Security > Edit. Ensure IIS_IUSRS has appropriate read permissions. 
3. Create the IIS Site 
	Open IIS Manager.
	In the Connections pane, right-click Sites > Add Website.
	Fill in the details:
	Site name: A friendly name (e.g., mipsdk).
	Physical path: The path to the folder from Step 2 (e.g., C:\inetpub\wwwroot\MyApi).
	Port: Assign a port (e.g., 80 or 8085).
	Click OK. 
4. Configure the Application Pool 
	ASP.NET Core runs in a separate process, so the application pool does not need to load the .NET CLR. 
	In IIS Manager, click Application Pools.
	Select the pool corresponding to your site, right-click, and select Basic Settings.
	Set .NET CLR version to No Managed Code.
	Click OK. 
5. Test the API 
