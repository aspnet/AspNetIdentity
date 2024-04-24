// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using static System.Net.Mime.MediaTypeNames;

namespace Microsoft.AspNet.Identity.AspNetCore
{
    /// <summary>
    ///     OwinMiddleware that initializes an object for use in the OwinContext via the Get/Set generic extensions method
    /// </summary>
    /// <typeparam name="TResult"></typeparam>
    /// <typeparam name="TOptions"></typeparam>
    public class IdentityFactoryMiddleware<TResult, TOptions> : IMiddleware
        where TResult : IDisposable
        where TOptions : IdentityFactoryOptions<TResult>
    {
        /// <summary>
        ///     Constructor
        /// </summary>
        /// <param name="options">Configuration options for the middleware</param>
        public IdentityFactoryMiddleware(TOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }
            if (options.Provider == null)
            {
                throw new ArgumentNullException("options.Provider");
            }
            Options = options;
        }

        /// <summary>
        ///     Configuration options
        /// </summary>
        public TOptions Options { get; private set; }

        /// <summary>
        ///     Create an object using the Options.Provider, storing it in the OwinContext and then disposes the object when finished
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public async Task InvokeAsync(HttpContext context, RequestDelegate next)
        {
            var instance = Options.Provider.Create(Options, context);
            try
            {
                context.Set(instance);
                if (next != null)
                {
                    await next.Invoke(context);
                }
            }
            finally
            {
                Options.Provider.Dispose(Options, instance);
            }
        }
    }
}