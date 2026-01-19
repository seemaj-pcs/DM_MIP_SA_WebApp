using Microsoft.InformationProtection;

namespace DM_MIP_SA_WebApp.Services
{
    internal class ConsentDelegateImpl : IConsentDelegate
    {
        public Consent GetUserConsent(string url)
        {
            return Consent.Accept;
        }
    }
}
