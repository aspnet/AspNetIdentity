// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System.Threading.Tasks;

namespace Microsoft.AspNet.Identity
{
    /// <summary>
    ///     Stores a user's phone number
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    public interface IUserPhoneNumberStore<TUser> : IUserPhoneNumberStore<TUser, string>
        where TUser : class, IUser<string>
    {
    }

    /// <summary>
    ///     Stores a user's phone number
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    /// <typeparam name="TKey"></typeparam>
    public interface IUserPhoneNumberStore<TUser, in TKey> : IUserStore<TUser, TKey> where TUser : class, IUser<TKey>
    {
        /// <summary>
        ///     Set the user's phone number
        /// </summary>
        /// <param name="user"></param>
        /// <param name="phoneNumber"></param>
        /// <returns></returns>
        Task SetPhoneNumberAsync(TUser user, string phoneNumber);

        /// <summary>
        ///     Get the user phone number
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        Task<string> GetPhoneNumberAsync(TUser user);

        /// <summary>
        ///     Returns true if the user phone number is confirmed
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        Task<bool> GetPhoneNumberConfirmedAsync(TUser user);

        /// <summary>
        ///     Sets whether the user phone number is confirmed
        /// </summary>
        /// <param name="user"></param>
        /// <param name="confirmed"></param>
        /// <returns></returns>
        Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed);
    }
}