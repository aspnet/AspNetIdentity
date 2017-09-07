// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.Owin;

namespace Microsoft.AspNet.Identity.Owin
{
    /// <summary>
    ///     Used to configure how the IdentityFactoryMiddleware will create an instance of the specified type for each OwinContext
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public class IdentityFactoryProvider<T> : IIdentityFactoryProvider<T> where T : class, IDisposable
    {
        /// <summary>
        ///     Constructor
        /// </summary>
        public IdentityFactoryProvider()
        {
            OnDispose = (options, instance) => { };
            OnCreate = (options, context) => null;
        }

        /// <summary>
        ///     A delegate assigned to this property will be invoked when the related method is called
        /// </summary>
        public Func<IdentityFactoryOptions<T>, IOwinContext, T> OnCreate { get; set; }

        /// <summary>
        ///     A delegate assigned to this property will be invoked when the related method is called
        /// </summary>
        public Action<IdentityFactoryOptions<T>, T> OnDispose { get; set; }

        /// <summary>
        ///     Calls the OnCreate Delegate
        /// </summary>
        /// <param name="options"></param>
        /// <param name="context"></param>
        /// <returns></returns>
        public virtual T Create(IdentityFactoryOptions<T> options, IOwinContext context)
        {
            return OnCreate(options, context);
        }

        /// <summary>
        ///     Calls the OnDispose delegate
        /// </summary>
        /// <param name="options"></param>
        /// <param name="instance"></param>
        public virtual void Dispose(IdentityFactoryOptions<T> options, T instance)
        {
            OnDispose(options, instance);
        }
    }
}