// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Generic;
using System.Threading.Tasks;

namespace Microsoft.AspNet.Identity
{
    /// <summary>
    ///     Interface that maps users to login providers, i.e. Google, Facebook, Twitter, Microsoft
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    public interface IUserLoginStore<TUser> : IUserLoginStore<TUser, string> where TUser : class, IUser<string>
    {
    }

    /// <summary>
    ///     Interface that maps users to login providers, i.e. Google, Facebook, Twitter, Microsoft
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    /// <typeparam name="TKey"></typeparam>
    public interface IUserLoginStore<TUser, in TKey> : IUserStore<TUser, TKey> where TUser : class, IUser<TKey>
    {
        /// <summary>
        ///     Adds a user login with the specified provider and key
        /// </summary>
        /// <param name="user"></param>
        /// <param name="login"></param>
        /// <returns></returns>
        Task AddLoginAsync(TUser user, UserLoginInfo login);

        /// <summary>
        ///     Removes the user login with the specified combination if it exists
        /// </summary>
        /// <param name="user"></param>
        /// <param name="login"></param>
        /// <returns></returns>
        Task RemoveLoginAsync(TUser user, UserLoginInfo login);

        /// <summary>
        ///     Returns the linked accounts for this user
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user);

        /// <summary>
        ///     Returns the user associated with this login
        /// </summary>
        /// <returns></returns>
        Task<TUser> FindAsync(UserLoginInfo login);
    }
}