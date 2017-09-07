// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System.Linq;

namespace Microsoft.AspNet.Identity
{
    /// <summary>
    ///     Interface that exposes an IQueryable roles
    /// </summary>
    /// <typeparam name="TRole"></typeparam>
    public interface IQueryableRoleStore<TRole> : IQueryableRoleStore<TRole, string> where TRole : IRole<string>
    {
    }

    /// <summary>
    ///     Interface that exposes an IQueryable roles
    /// </summary>
    /// <typeparam name="TRole"></typeparam>
    /// <typeparam name="TKey"></typeparam>
    public interface IQueryableRoleStore<TRole, in TKey> : IRoleStore<TRole, TKey> where TRole : IRole<TKey>
    {
        /// <summary>
        ///     IQueryable Roles
        /// </summary>
        IQueryable<TRole> Roles { get; }
    }
}