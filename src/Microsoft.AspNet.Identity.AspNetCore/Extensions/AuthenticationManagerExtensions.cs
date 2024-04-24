// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore
{
    /// <summary>
    ///     Extensions methods on IAuthenticationManager that add methods for using the default Application and External
    ///     authentication type constants
    /// </summary>
    internal static class AuthenticationManagerExtensions
    {
        /// <summary>
        ///     Returns true if there is a TwoFactorRememberBrowser cookie for a user
        /// </summary>
        /// <param name="manager"></param>
        /// <param name="userId"></param>
        /// <returns></returns>
        internal static async Task<bool> TwoFactorBrowserRememberedAsync(this HttpContext manager,
            string userId)
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }
            var result =
                await manager.AuthenticateAsync(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie).WithCurrentCulture();
            return (result?.Principal?.Identity is ClaimsIdentity claimsIdentity && claimsIdentity.GetUserId() == userId);
        }

        /// <summary>
        ///     Creates a TwoFactorRememberBrowser cookie for a user
        /// </summary>
        /// <param name="manager"></param>
        /// <param name="userId"></param>
        /// <returns></returns>
        internal static ClaimsIdentity CreateTwoFactorRememberBrowserIdentity(this HttpContext manager,
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