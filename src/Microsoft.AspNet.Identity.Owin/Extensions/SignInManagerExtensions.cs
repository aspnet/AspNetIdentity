// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Security.Claims;

namespace Microsoft.AspNet.Identity.Owin
{
    /// <summary>
    ///     Extension methods for SignInManager/>
    /// </summary>
    public static class SignInManagerExtensions
    {
        /// <summary>
        /// Called to generate the ClaimsIdentity for the user, override to add additional claims before SignIn
        /// </summary>
        /// <param name="manager"></param>
        /// <param name="user"></param>
        /// <returns></returns>
        public static ClaimsIdentity CreateUserIdentity<TUser, TKey>(this SignInManager<TUser, TKey> manager, TUser user)
            where TKey : IEquatable<TKey>
            where TUser : class, IUser<TKey>
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }
            return AsyncHelper.RunSync(() => manager.CreateUserIdentityAsync(user));
        }

        /// <summary>
        /// Creates a user identity and then signs the identity using the AuthenticationManager
        /// </summary>
        /// <param name="manager"></param>
        /// <param name="user"></param>
        /// <param name="isPersistent"></param>
        /// <param name="rememberBrowser"></param>
        /// <returns></returns>
        public static void SignIn<TUser, TKey>(this SignInManager<TUser, TKey> manager, TUser user, bool isPersistent, bool rememberBrowser)
            where TKey : IEquatable<TKey>
            where TUser : class, IUser<TKey>
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }
            AsyncHelper.RunSync(() => manager.SignInAsync(user, isPersistent, rememberBrowser));
        }

        /// <summary>
        /// Send a two factor code to a user
        /// </summary>
        /// <param name="manager"></param>
        /// <param name="provider"></param>
        /// <returns></returns>
        public static bool SendTwoFactorCode<TUser, TKey>(this SignInManager<TUser, TKey> manager, string provider)
            where TKey : IEquatable<TKey>
            where TUser : class, IUser<TKey>
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }
            return AsyncHelper.RunSync(() => manager.SendTwoFactorCodeAsync(provider));
        }

        /// <summary>
        /// Get the user id that has been verified already or null.
        /// </summary>
        /// <param name="manager"></param>
        /// <returns></returns>
        public static TKey GetVerifiedUserId<TUser, TKey>(this SignInManager<TUser, TKey> manager)
            where TKey : IEquatable<TKey>
            where TUser : class, IUser<TKey>
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }
            return AsyncHelper.RunSync(() => manager.GetVerifiedUserIdAsync());
        }

        /// <summary>
        /// Has the user been verified (ie either via password or external login)
        /// </summary>
        /// <param name="manager"></param>
        /// <returns></returns>
        public static bool HasBeenVerified<TUser, TKey>(this SignInManager<TUser, TKey> manager)
            where TKey : IEquatable<TKey>
            where TUser : class, IUser<TKey>
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }
            return AsyncHelper.RunSync(() => manager.HasBeenVerifiedAsync());
        }

        /// <summary>
        /// Two factor verification step
        /// </summary>
        /// <param name="manager"></param>
        /// <param name="provider"></param>
        /// <param name="code"></param>
        /// <param name="isPersistent"></param>
        /// <param name="rememberBrowser"></param>
        /// <returns></returns>
        public static SignInStatus TwoFactorSignIn<TUser, TKey>(this SignInManager<TUser, TKey> manager, string provider, string code, bool isPersistent, bool rememberBrowser)
            where TKey : IEquatable<TKey>
            where TUser : class, IUser<TKey>
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }
            return AsyncHelper.RunSync(() => manager.TwoFactorSignInAsync(provider, code, isPersistent, rememberBrowser));
        }

        /// <summary>
        /// Sign the user in using an associated external login
        /// </summary>
        /// <param name="manager"></param>
        /// <param name="loginInfo"></param>
        /// <param name="isPersistent"></param>
        /// <returns></returns>
        public static SignInStatus ExternalSignIn<TUser, TKey>(this SignInManager<TUser, TKey> manager, ExternalLoginInfo loginInfo, bool isPersistent)
            where TKey : IEquatable<TKey>
            where TUser : class, IUser<TKey>
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }
            return AsyncHelper.RunSync(() => manager.ExternalSignInAsync(loginInfo, isPersistent));
        }


        /// <summary>
        /// Sign in the user in using the user name and password
        /// </summary>
        /// <param name="manager"></param>
        /// <param name="userName"></param>
        /// <param name="password"></param>
        /// <param name="isPersistent"></param>
        /// <param name="shouldLockout"></param>
        /// <returns></returns>
        public static SignInStatus PasswordSignIn<TUser, TKey>(this SignInManager<TUser, TKey> manager, string userName, string password, bool isPersistent, bool shouldLockout)
            where TKey : IEquatable<TKey>
            where TUser : class, IUser<TKey>
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }
            return AsyncHelper.RunSync(() => manager.PasswordSignInAsync(userName, password, isPersistent, shouldLockout));
        }
    }
}