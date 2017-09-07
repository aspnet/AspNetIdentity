// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Globalization;
using System.Threading.Tasks;

namespace Microsoft.AspNet.Identity
{
    /// <summary>
    ///     Used to validate that passwords are a minimum length
    /// </summary>
    public class MinimumLengthValidator : IIdentityValidator<string>
    {
        /// <summary>
        ///     Constructor
        /// </summary>
        /// <param name="requiredLength"></param>
        public MinimumLengthValidator(int requiredLength)
        {
            RequiredLength = requiredLength;
        }

        /// <summary>
        ///     Minimum required length for the password
        /// </summary>
        public int RequiredLength { get; set; }

        /// <summary>
        ///     Ensures that the password is of the required length
        /// </summary>
        /// <param name="item"></param>
        /// <returns></returns>
        public virtual Task<IdentityResult> ValidateAsync(string item)
        {
            if (string.IsNullOrWhiteSpace(item) || item.Length < RequiredLength)
            {
                return
                    Task.FromResult(
                        IdentityResult.Failed(String.Format(CultureInfo.CurrentCulture, Resources.PasswordTooShort,
                            RequiredLength)));
            }
            return Task.FromResult(IdentityResult.Success);
        }
    }
}