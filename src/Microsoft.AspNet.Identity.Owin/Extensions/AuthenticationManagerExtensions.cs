// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;

namespace Microsoft.Owin.Security
{
    /// <summary>
    ///     Extensions methods on IAuthenticationManager that add methods for using the default Application and External
    ///     authentication type constants
    /// </summary>
    public static class AuthenticationManagerExtensions
    {
        /// <summary>
        ///     Return the authentication types which are considered external because they have captions
        /// </summary>
        /// <param name="manager"></param>
        /// <returns></returns>
        public static IEnumerable<AuthenticationDescription> GetExternalAuthenticationTypes(
            this IAuthenticationManager manager)
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }
            return manager.GetAuthenticationTypes(d => d.Properties != null && d.Properties.ContainsKey("Caption"));
        }

        /// <summary>
        ///     Return the identity associated with the default external authentication type
        /// </summary>
        /// <returns></returns>
        public static async Task<ClaimsIdentity> GetExternalIdentityAsync(this IAuthenticationManager manager,
            string externalAuthenticationType)
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }
            var result = await manager.AuthenticateAsync(externalAuthenticationType).WithCurrentCulture();
            if (result != null && result.Identity != null &&
                result.Identity.FindFirst(ClaimTypes.NameIdentifier) != null)
            {
                return result.Identity;
            }
            return null;
        }

        /// <summary>
        /// Return the identity associated with the default external authentication type
        /// </summary>
        /// <param name="manager"></param>
        /// <param name="externalAuthenticationType"></param>
        /// <returns></returns>
        public static ClaimsIdentity GetExternalIdentity(this IAuthenticationManager manager,
            string externalAuthenticationType)
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }
            return AsyncHelper.RunSync(() => manager.GetExternalIdentityAsync(externalAuthenticationType));
        }

        private static ExternalLoginInfo GetExternalLoginInfo(AuthenticateResult result)
        {
            if (result == null || result.Identity == null)
            {
                return null;
            }
            var idClaim = result.Identity.FindFirst(ClaimTypes.NameIdentifier);
            if (idClaim == null)
            {
                return null;
            }
            // By default we don't allow spaces in user names
            var name = result.Identity.Name;
            if (name != null)
            {
                name = name.Replace(" ", "");
            }
            var email = result.Identity.FindFirstValue(ClaimTypes.Email);
            return new ExternalLoginInfo
            {
                ExternalIdentity = result.Identity,
                Login = new UserLoginInfo(idClaim.Issuer, idClaim.Value),
                DefaultUserName = name,
                Email = email
            };
        }

        /// <summary>
        ///     Extracts login info out of an external identity
        /// </summary>
        /// <param name="manager"></param>
        /// <returns></returns>
        public static async Task<ExternalLoginInfo> GetExternalLoginInfoAsync(this IAuthenticationManager manager)
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }
            return GetExternalLoginInfo(await manager.AuthenticateAsync(DefaultAuthenticationTypes.ExternalCookie).WithCurrentCulture());
        }

        /// <summary>
        ///     Extracts login info out of an external identity
        /// </summary>
        /// <param name="manager"></param>
        /// <returns></returns>
        public static ExternalLoginInfo GetExternalLoginInfo(this IAuthenticationManager manager)
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }
            return AsyncHelper.RunSync(manager.GetExternalLoginInfoAsync);
        }

        /// <summary>
        ///     Extracts login info out of an external identity
        /// </summary>
        /// <param name="manager"></param>
        /// <param name="xsrfKey">key that will be used to find the userId to verify</param>
        /// <param name="expectedValue">
        ///     the value expected to be found using the xsrfKey in the AuthenticationResult.Properties
        ///     dictionary
        /// </param>
        /// <returns></returns>
        public static ExternalLoginInfo GetExternalLoginInfo(this IAuthenticationManager manager, string xsrfKey,
            string expectedValue)
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }
            return AsyncHelper.RunSync(() => manager.GetExternalLoginInfoAsync(xsrfKey, expectedValue));
        }

        /// <summary>
        ///     Extracts login info out of an external identity
        /// </summary>
        /// <param name="manager"></param>
        /// <param name="xsrfKey">key that will be used to find the userId to verify</param>
        /// <param name="expectedValue">
        ///     the value expected to be found using the xsrfKey in the AuthenticationResult.Properties
        ///     dictionary
        /// </param>
        /// <returns></returns>
        public static async Task<ExternalLoginInfo> GetExternalLoginInfoAsync(this IAuthenticationManager manager,
            string xsrfKey, string expectedValue)
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }
            var result = await manager.AuthenticateAsync(DefaultAuthenticationTypes.ExternalCookie).WithCurrentCulture();
            // Verify that the userId is the same as what we expect if requested
            if (result != null &&
                result.Properties != null &&
                result.Properties.Dictionary != null &&
                result.Properties.Dictionary.ContainsKey(xsrfKey) &&
                result.Properties.Dictionary[xsrfKey] == expectedValue)
            {
                return GetExternalLoginInfo(result);
            }
            return null;
        }

        /// <summary>
        ///     Returns true if there is a TwoFactorRememberBrowser cookie for a user
        /// </summary>
        /// <param name="manager"></param>
        /// <param name="userId"></param>
        /// <returns></returns>
        public static async Task<bool> TwoFactorBrowserRememberedAsync(this IAuthenticationManager manager,
            string userId)
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }
            var result =
                await manager.AuthenticateAsync(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie).WithCurrentCulture();
            return (result != null && result.Identity != null && result.Identity.GetUserId() == userId);
        }

        /// <summary>
        ///     Returns true if there is a TwoFactorRememberBrowser cookie for a user
        /// </summary>
        /// <param name="manager"></param>
        /// <param name="userId"></param>
        /// <returns></returns>
        public static bool TwoFactorBrowserRemembered(this IAuthenticationManager manager,
            string userId)
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }
            return AsyncHelper.RunSync(() => manager.TwoFactorBrowserRememberedAsync(userId));
        }

        /// <summary>
        ///     Creates a TwoFactorRememberBrowser cookie for a user
        /// </summary>
        /// <param name="manager"></param>
        /// <param name="userId"></param>
        /// <returns></returns>
        public static ClaimsIdentity CreateTwoFactorRememberBrowserIdentity(this IAuthenticationManager manager,
            string userId)
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }
            var rememberBrowserIdentity = new ClaimsIdentity(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);
            rememberBrowserIdentity.AddClaim(new Claim(ClaimTypes.NameIdentifier, userId));
            return rememberBrowserIdentity;
        }
    }
}