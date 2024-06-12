// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.DataProtection;
using Moq;
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

        [Fact]
        public async Task PasswordSignInFailsWhenResetLockoutFails()
        {
            // Setup
            var owinContext = new OwinContext();
            await TestUtil.CreateManager(owinContext);
            var manager = new Mock<UserManager<IdentityUser>>(Mock.Of<IUserStore<IdentityUser>>());
            var user = new IdentityUser("SignInTest");
            manager.Setup(m => m.FindByNameAsync(user.Id)).Returns(Task.FromResult(user)).Verifiable();
            manager.Setup(m => m.IsLockedOutAsync(user.Id)).Returns(Task.FromResult(false)).Verifiable();
            manager.Setup(m => m.CheckPasswordAsync(user, "[PLACEHOLDER]-1a")).Returns(Task.FromResult(true)).Verifiable();
            manager.Setup(m => m.GetTwoFactorEnabledAsync(user.Id)).Returns(Task.FromResult(false)).Verifiable();
            manager.Setup(m => m.ResetAccessFailedCountAsync(user.Id)).Returns(Task.FromResult(IdentityResult.Failed())).Verifiable();

            var signInManager = new SignInManager<IdentityUser, string>(manager.Object, owinContext.Authentication);

            // Act
            var result = await signInManager.PasswordSignInAsync(user.Id, "[PLACEHOLDER]-1a", isPersistent: false, shouldLockout: false);

            // Assert
            Assert.Equal(SignInStatus.Failure, result);
            manager.Verify();
        }
    }
}
