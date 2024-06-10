// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNet.Identity.AspNetCore
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
        T Create(IdentityFactoryOptions<T> options, HttpContext context);

        /// <summary>
        ///     Called at the end of the request to dispose the object created
        /// </summary>
        /// <param name="options"></param>
        /// <param name="instance"></param>
        void Dispose(IdentityFactoryOptions<T> options, T instance);
    }
}