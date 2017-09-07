// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.Owin;

namespace Microsoft.AspNet.Identity.Owin
{
    /// <summary>
    ///     Extension methods for OwinContext/>
    /// </summary>
    public static class OwinContextExtensions
    {
        private static readonly string IdentityKeyPrefix = "AspNet.Identity.Owin:";

        private static string GetKey(Type t)
        {
            return IdentityKeyPrefix + t.AssemblyQualifiedName;
        }

        /// <summary>
        ///     Stores an object in the OwinContext using a key based on the AssemblyQualified type name
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="context"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public static IOwinContext Set<T>(this IOwinContext context, T value)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }
            return context.Set(GetKey(typeof (T)), value);
        }

        /// <summary>
        ///     Retrieves an object from the OwinContext using a key based on the AssemblyQualified type name
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="context"></param>
        /// <returns></returns>
        public static T Get<T>(this IOwinContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }
            return context.Get<T>(GetKey(typeof (T)));
        }

        /// <summary>
        ///     Get the user manager from the context
        /// </summary>
        /// <typeparam name="TManager"></typeparam>
        /// <param name="context"></param>
        /// <returns></returns>
        public static TManager GetUserManager<TManager>(this IOwinContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }
            return context.Get<TManager>();
        }
    }
}