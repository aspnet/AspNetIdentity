// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.Owin.Security.DataProtection;

namespace Microsoft.AspNet.Identity.Owin
{
    /// <summary>
    ///     Configuration options for a IdentityFactoryMiddleware
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public class IdentityFactoryOptions<T> where T : IDisposable
    {
        /// <summary>
        ///     Used to configure the data protection provider
        /// </summary>
        public IDataProtectionProvider DataProtectionProvider { get; set; }

        /// <summary>
        ///     Provider used to Create and Dispose objects
        /// </summary>
        public IIdentityFactoryProvider<T> Provider { get; set; }
    }
}