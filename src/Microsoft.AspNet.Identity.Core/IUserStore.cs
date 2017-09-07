// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Threading.Tasks;

namespace Microsoft.AspNet.Identity
{
    /// <summary>
    ///     Interface that exposes basic user management apis
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    public interface IUserStore<TUser> : IUserStore<TUser, string> where TUser : class, IUser<string>
    {
    }

    /// <summary>
    ///     Interface that exposes basic user management apis
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    /// <typeparam name="TKey"></typeparam>
    public interface IUserStore<TUser, in TKey> : IDisposable where TUser : class, IUser<TKey>
    {
        /// <summary>
        ///     Insert a new user
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        Task CreateAsync(TUser user);

        /// <summary>
        ///     Update a user
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        Task UpdateAsync(TUser user);

        /// <summary>
        ///     Delete a user
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        Task DeleteAsync(TUser user);

        /// <summary>
        ///     Finds a user
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        Task<TUser> FindByIdAsync(TKey userId);

        /// <summary>
        ///     Find a user by name
        /// </summary>
        /// <param name="userName"></param>
        /// <returns></returns>
        Task<TUser> FindByNameAsync(string userName);
    }
}