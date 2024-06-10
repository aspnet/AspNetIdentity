// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNet.Identity.AspNetCore
{
    /// <summary>
    ///     Extension methods for OwinContext/>
    /// </summary>
    internal static class HttpContextExtensions
    {
        /// <summary>
        ///     Stores an object in the OwinContext using a key based on the AssemblyQualified type name
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="context"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        internal static HttpContext Set<T>(this HttpContext context, T value)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            context.Items[typeof(T)] = value;
            return context;
        }

        /// <summary>
        ///     Retrieves an object from the OwinContext using a key based on the AssemblyQualified type name
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="context"></param>
        /// <returns></returns>
        internal static T Get<T>(this HttpContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }
            return (T)context.Items[typeof(T)];
        }

        /// <summary>
        ///     Get the user manager from the context
        /// </summary>
        /// <typeparam name="TManager"></typeparam>
        /// <param name="context"></param>
        /// <returns></returns>
        internal static TManager GetUserManager<TManager>(this HttpContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }
            return context.Get<TManager>();
        }
    }
}