// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System.Threading.Tasks;

namespace Microsoft.AspNet.Identity {
    /// <summary>
    ///     Stores whether two factor authentication is enabled for a user
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    /// <typeparam name="TKey"></typeparam>
    public interface IUserTwoFactorStore<TUser, in TKey> : IUserStore<TUser, TKey> where TUser : class, IUser<TKey> {
        /// <summary>
        ///     Sets whether two factor authentication is enabled for the user
        /// </summary>
        /// <param name="user"></param>
        /// <param name="enabled"></param>
        /// <returns></returns>
        Task SetTwoFactorEnabledAsync(TUser user, bool enabled);

        /// <summary>
        ///     Returns whether two factor authentication is enabled for the user
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        Task<bool> GetTwoFactorEnabledAsync(TUser user);
    }
}