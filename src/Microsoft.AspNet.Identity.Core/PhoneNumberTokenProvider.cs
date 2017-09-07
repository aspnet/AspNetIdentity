// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Globalization;
using System.Threading.Tasks;

namespace Microsoft.AspNet.Identity
{
    /// <summary>
    ///     TokenProvider that generates tokens from the user's security stamp and notifies a user via their phone number
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    public class PhoneNumberTokenProvider<TUser> : PhoneNumberTokenProvider<TUser, string>
        where TUser : class, IUser<string>
    {
    }

    /// <summary>
    ///     TokenProvider that generates tokens from the user's security stamp and notifies a user via their phone number
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    /// <typeparam name="TKey"></typeparam>
    public class PhoneNumberTokenProvider<TUser, TKey> : TotpSecurityStampBasedTokenProvider<TUser, TKey>
        where TUser : class, IUser<TKey>
        where TKey : IEquatable<TKey>
    {
        private string _body;

        /// <summary>
        ///     Message contents which should contain a format string which the token will be the only argument
        /// </summary>
        public string MessageFormat
        {
            get { return _body ?? "{0}"; }
            set { _body = value; }
        }

        /// <summary>
        ///     Returns true if the user has a phone number set
        /// </summary>
        /// <param name="manager"></param>
        /// <param name="user"></param>
        /// <returns></returns>
        public override async Task<bool> IsValidProviderForUserAsync(UserManager<TUser, TKey> manager, TUser user)
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }
            var phoneNumber = await manager.GetPhoneNumberAsync(user.Id).WithCurrentCulture();
            return !String.IsNullOrWhiteSpace(phoneNumber) && await manager.IsPhoneNumberConfirmedAsync(user.Id).WithCurrentCulture();
        }

        /// <summary>
        ///     Returns the phone number of the user for entropy in the token
        /// </summary>
        /// <param name="purpose"></param>
        /// <param name="manager"></param>
        /// <param name="user"></param>
        /// <returns></returns>
        public override async Task<string> GetUserModifierAsync(string purpose, UserManager<TUser, TKey> manager,
            TUser user)
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }
            var phoneNumber = await manager.GetPhoneNumberAsync(user.Id).WithCurrentCulture();
            return "PhoneNumber:" + purpose + ":" + phoneNumber;
        }

        /// <summary>
        ///     Notifies the user with a token via sms using the MessageFormat
        /// </summary>
        /// <param name="token"></param>
        /// <param name="manager"></param>
        /// <param name="user"></param>
        /// <returns></returns>
        public override Task NotifyAsync(string token, UserManager<TUser, TKey> manager, TUser user)
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }
            return manager.SendSmsAsync(user.Id, String.Format(CultureInfo.CurrentCulture, MessageFormat, token));
        }
    }
}