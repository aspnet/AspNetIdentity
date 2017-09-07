// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

namespace Microsoft.AspNet.Identity.Owin
{
    /// <summary>
    /// Possible results from a sign in attempt
    /// </summary>
    public enum SignInStatus
    {
        /// <summary>
        /// Sign in was successful
        /// </summary>
        Success,

        /// <summary>
        /// User is locked out
        /// </summary>
        LockedOut,

        /// <summary>
        /// Sign in requires addition verification (i.e. two factor)
        /// </summary>
        RequiresVerification,

        /// <summary>
        /// Sign in failed
        /// </summary>
        Failure
    }

}