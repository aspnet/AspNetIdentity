// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.DataProtection;
using Xunit;
using Xunit.Extensions;

namespace Identity.Test
{
    public class SignInManagerTest
    {
        [Theory]
        [InlineData(true, true)]
        [InlineData(true, false)]
        [InlineData(false, true)]
        [InlineData(false, false)]
        public async Task SignInAsyncCookiePersistenceTest(bool isPersistent, bool rememberBrowser)
        {
            var owinContext = new OwinContext();
            await TestUtil.CreateManager(owinContext);
            var manager = owinContext.GetUserManager<UserManager<IdentityUser>>();
            var user = new IdentityUser("SignInTest");
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            var signInManager = new SignInManager<IdentityUser, string>(manager, owinContext.Authentication);

            await signInManager.SignInAsync(user, isPersistent, rememberBrowser);

            Assert.Equal(isPersistent, owinContext.Authentication.AuthenticationResponseGrant.Properties.IsPersistent);
        }
        
    }
}
