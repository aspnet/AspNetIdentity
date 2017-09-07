// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Threading.Tasks;

namespace Microsoft.AspNet.Identity
{
    /// <summary>
    ///     Interface that exposes basic role management
    /// </summary>
    /// <typeparam name="TRole"></typeparam>
    public interface IRoleStore<TRole> : IRoleStore<TRole, string> where TRole : IRole<string>
    {
    }

    /// <summary>
    ///     Interface that exposes basic role management
    /// </summary>
    /// <typeparam name="TRole"></typeparam>
    /// <typeparam name="TKey"></typeparam>
    public interface IRoleStore<TRole, in TKey> : IDisposable where TRole : IRole<TKey>
    {
        /// <summary>
        ///     Create a new role
        /// </summary>
        /// <param name="role"></param>
        /// <returns></returns>
        Task CreateAsync(TRole role);

        /// <summary>
        ///     Update a role
        /// </summary>
        /// <param name="role"></param>
        /// <returns></returns>
        Task UpdateAsync(TRole role);

        /// <summary>
        ///     Delete a role
        /// </summary>
        /// <param name="role"></param>
        /// <returns></returns>
        Task DeleteAsync(TRole role);

        /// <summary>
        ///     Find a role by id
        /// </summary>
        /// <param name="roleId"></param>
        /// <returns></returns>
        Task<TRole> FindByIdAsync(TKey roleId);

        /// <summary>
        ///     Find a role by name
        /// </summary>
        /// <param name="roleName"></param>
        /// <returns></returns>
        Task<TRole> FindByNameAsync(string roleName);
    }
}