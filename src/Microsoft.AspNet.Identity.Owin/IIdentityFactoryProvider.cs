// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.Owin;

namespace Microsoft.AspNet.Identity.Owin
{
    /// <summary>
    ///     Interface used to create objects per request
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public interface IIdentityFactoryProvider<T> where T : IDisposable
    {
        /// <summary>
        ///     Called once per request to create an object
        /// </summary>
        /// <param name="options"></param>
        /// <param name="context"></param>
        /// <returns></returns>
        T Create(IdentityFactoryOptions<T> options, IOwinContext context);

        /// <summary>
        ///     Called at the end of the request to dispose the object created
        /// </summary>
        /// <param name="options"></param>
        /// <param name="instance"></param>
        void Dispose(IdentityFactoryOptions<T> options, T instance);
    }
}