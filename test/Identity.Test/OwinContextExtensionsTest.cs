// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

#if NETFRAMEWORK
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
#else 
using Microsoft.AspNet.Identity.AspNetCore;
using Microsoft.AspNetCore.Http;
#endif 
using Xunit;

namespace Identity.Test
{
    public class OwinContextExtensionsTest
    {
        [Fact]
        public void MiddlewareExtensionsNullCheckTest()
        {
#if NETFRAMEWORK
            IOwinContext context = null;
#else
            HttpContext context = null;
#endif
            ExceptionHelper.ThrowsArgumentNull(() => context.Get<object>(), "context");
            ExceptionHelper.ThrowsArgumentNull(() => context.GetUserManager<object>(), "context");
            ExceptionHelper.ThrowsArgumentNull(() => context.Set<object>(null), "context");
        }
    }
}