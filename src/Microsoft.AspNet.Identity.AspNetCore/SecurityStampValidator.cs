// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;


namespace Microsoft.AspNet.Identity.AspNetCore
{
    /// <summary>
    ///     Static helper class used to configure a CookieAuthenticationProvider to validate a cookie against a user's security
    ///     stamp
    /// </summary>
    public static class SecurityStampValidator
    {
        /// <summary>
        ///     Can be used as the ValidateIdentity method for a CookieAuthenticationProvider which will check a user's security
        ///     stamp after validateInterval
        ///     Rejects the identity if the stamp changes, and otherwise will call regenerateIdentity to sign in a new
        ///     ClaimsIdentity
        /// </summary>
        /// <typeparam name="TManager"></typeparam>
        /// <typeparam name="TUser"></typeparam>
        /// <param name="validateInterval"></param>
        /// <param name="regenerateIdentity"></param>
        /// <returns></returns>
        public static Func<CookieValidatePrincipalContext, Task> OnValidateIdentity<TManager, TUser>(
            TimeSpan validateInterval, Func<TManager, TUser, Task<ClaimsIdentity>> regenerateIdentity)
            where TManager : UserManager<TUser, string>
            where TUser : class, IUser<string>
        {
            return OnValidateIdentity(validateInterval, regenerateIdentity, id => id.GetUserId());
        }

        /// <summary>
        ///     Can be used as the ValidateIdentity method for a CookieAuthenticationProvider which will check a user's security
        ///     stamp after validateInterval
        ///     Rejects the identity if the stamp changes, and otherwise will call regenerateIdentity to sign in a new
        ///     ClaimsIdentity
        /// </summary>
        /// <typeparam name="TManager"></typeparam>
        /// <typeparam name="TUser"></typeparam>
        /// <typeparam name="TKey"></typeparam>
        /// <param name="validateInterval"></param>
        /// <param name="regenerateIdentityCallback"></param>
        /// <param name="getUserIdCallback"></param>
        /// <returns></returns>
        public static Func<CookieValidatePrincipalContext, Task> OnValidateIdentity<TManager, TUser, TKey>(
            TimeSpan validateInterval, Func<TManager, TUser, Task<ClaimsIdentity>> regenerateIdentityCallback,
            Func<ClaimsIdentity, TKey> getUserIdCallback)
            where TManager : UserManager<TUser, TKey>
            where TUser : class, IUser<TKey>
            where TKey : IEquatable<TKey>
        {
            if (getUserIdCallback == null)
            {
                throw new ArgumentNullException("getUserIdCallback");
            }
            return async context =>
            {
                var currentUtc = DateTimeOffset.UtcNow;
                //if (context.Options != null && context.Options.SystemClock != null)
                //{
                //    currentUtc = context.Options.SystemClock.UtcNow;
                //}
                var issuedUtc = context.Properties.IssuedUtc;

                // Only validate if enough time has elapsed
                var validate = (issuedUtc == null);
                if (issuedUtc != null)
                {
                    var timeElapsed = currentUtc.Subtract(issuedUtc.Value);
                    validate = timeElapsed > validateInterval;
                }
                if (validate && context.Principal?.Identity is ClaimsIdentity claimsIdentity)
                {
                    var manager = context.HttpContext.GetUserManager<TManager>();
                    var userId = getUserIdCallback(claimsIdentity);
                    if (manager != null && userId != null)
                    {
                        var user = await manager.FindByIdAsync(userId).WithCurrentCulture();
                        var reject = true;
                        // Refresh the identity if the stamp matches, otherwise reject
                        if (user != null && manager.SupportsUserSecurityStamp)
                        {
                            var securityStamp =
                                claimsIdentity.FindFirstValue(Constants.DefaultSecurityStampClaimType);
                            if (securityStamp == await manager.GetSecurityStampAsync(userId).WithCurrentCulture())
                            {
                                reject = false;
                                // Regenerate fresh claims if possible and resign in
                                if (regenerateIdentityCallback != null)
                                {
                                    var identity = await regenerateIdentityCallback.Invoke(manager, user).WithCurrentCulture();
                                    if (identity != null)
                                    {
                                        // Fix for regression where this value is not updated
                                        // Setting it to null so that it is refreshed by the cookie middleware
                                        await context.HttpContext.SignInAsync(new ClaimsPrincipal(identity), context.Properties);
                                        
                                        // moved after SignIn so the test passes
                                        context.Properties.IssuedUtc = null;
                                        context.Properties.ExpiresUtc = null;
                                    }
                                }
                            }
                        }
                        if (reject)
                        {
                            context.RejectPrincipal();
                            await context.HttpContext.SignOutAsync();
                        }
                    }
                }
            };
        }
    }
}