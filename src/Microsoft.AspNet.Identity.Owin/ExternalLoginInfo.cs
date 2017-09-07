// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System.Security.Claims;

namespace Microsoft.AspNet.Identity.Owin
{
    /// <summary>
    ///     Used to return information needed to associate an external login
    /// </summary>
    public class ExternalLoginInfo
    {
        /// <summary>
        ///     Associated login data
        /// </summary>
        public UserLoginInfo Login { get; set; }

        /// <summary>
        ///     Suggested user name for a user
        /// </summary>
        public string DefaultUserName { get; set; }

        /// <summary>
        ///     Email claim from the external identity
        /// </summary>
        public string Email { get; set; }

        /// <summary>
        ///     The external identity
        /// </summary>
        public ClaimsIdentity ExternalIdentity { get; set; }
    }
}