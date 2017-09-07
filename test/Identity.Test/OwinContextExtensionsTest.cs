// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Xunit;

namespace Identity.Test
{
    public class OwinContextExtensionsTest
    {
        [Fact]
        public void MiddlewareExtensionsNullCheckTest()
        {
            IOwinContext context = null;
            ExceptionHelper.ThrowsArgumentNull(() => context.Get<object>(), "context");
            ExceptionHelper.ThrowsArgumentNull(() => context.GetUserManager<object>(), "context");
            ExceptionHelper.ThrowsArgumentNull(() => context.Set<object>(null), "context");
        }
    }
}