// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System.Threading.Tasks;

namespace Microsoft.AspNet.Identity
{
    /// <summary>
    ///     Used to validate an item
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public interface IIdentityValidator<in T>
    {
        /// <summary>
        ///     Validate the item
        /// </summary>
        /// <param name="item"></param>
        /// <returns></returns>
        Task<IdentityResult> ValidateAsync(T item);
    }
}