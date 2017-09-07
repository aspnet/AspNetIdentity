// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Microsoft.AspNet.Identity
{
    /// <summary>
    ///     Interface for creating a ClaimsIdentity from an IUser
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    /// <typeparam name="TKey"></typeparam>
    public interface IClaimsIdentityFactory<TUser, TKey>
        where TUser : class, IUser<TKey>
        where TKey : IEquatable<TKey>
    {
        /// <summary>
        ///     Create a ClaimsIdentity from an user using a UserManager
        /// </summary>
        /// <param name="manager"></param>
        /// <param name="user"></param>
        /// <param name="authenticationType"></param>
        /// <returns></returns>
        Task<ClaimsIdentity> CreateAsync(UserManager<TUser, TKey> manager, TUser user, string authenticationType);
    }

    /// <summary>
    ///     Interface for creating a ClaimsIdentity from a user
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    public interface IClaimsIdentityFactory<TUser> where TUser : class, IUser
    {
        /// <summary>
        ///     Create a ClaimsIdentity from an user using a UserManager
        /// </summary>
        /// <param name="manager"></param>
        /// <param name="user"></param>
        /// <param name="authenticationType"></param>
        /// <returns></returns>
        Task<ClaimsIdentity> CreateAsync(UserManager<TUser> manager, TUser user, string authenticationType);
    }
}