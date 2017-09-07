// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System.Linq;

namespace Microsoft.AspNet.Identity
{
    /// <summary>
    ///     Interface that exposes an IQueryable users
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    public interface IQueryableUserStore<TUser> : IQueryableUserStore<TUser, string> where TUser : class, IUser<string>
    {
    }

    /// <summary>
    ///     Interface that exposes an IQueryable users
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    /// <typeparam name="TKey"></typeparam>
    public interface IQueryableUserStore<TUser, in TKey> : IUserStore<TUser, TKey> where TUser : class, IUser<TKey>
    {
        /// <summary>
        ///     IQueryable users
        /// </summary>
        IQueryable<TUser> Users { get; }
    }
}