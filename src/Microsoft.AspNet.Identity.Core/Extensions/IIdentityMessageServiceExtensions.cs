using System;

namespace Microsoft.AspNet.Identity
{
    // Extension methods for IIdentityMessageService
    public static class IIdentityMessageServiceExtensions
    {
        /// <summary>
        /// Sync method to send the IdentityMessage
        /// </summary>
        /// <param name="service"></param>
        /// <param name="message"></param>
        public static void Send(this IIdentityMessageService service, IdentityMessage message)
        {
            if (service == null)
            {
                throw new ArgumentNullException("service");
            }

            AsyncHelper.RunSync(() => service.SendAsync(message));
        }
    }
}
