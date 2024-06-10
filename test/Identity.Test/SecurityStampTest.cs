// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;

#if NETFRAMEWORK
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.DataProtection;
#else
using Microsoft.AspNet.Identity.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
#endif

using Xunit;

namespace Identity.Test
{
    public class SecurityStampTest
    {
        [Fact]
        public async Task OnValidateIdentityNoBoomWithNullManagerTest()
        {
            var owinContext = GlobalHelpers.CreateContext();
            var id = new ClaimsIdentity(DefaultAuthenticationTypes.ApplicationCookie);
            var ticket = GlobalHelpers.CreateAuthenticationTicket(id, new AuthenticationProperties { IssuedUtc = DateTimeOffset.UtcNow });
            var context = GlobalHelpers.CreateCookieValidateIdentityContext(owinContext, ticket, new CookieAuthenticationOptions());
            await
                SecurityStampValidator.OnValidateIdentity<UserManager<IdentityUser>, IdentityUser>(TimeSpan.Zero, SignIn)
                    .Invoke(context);
            Assert.NotNull(context.ExtractClaimsIdentity());
        }

        [Fact]
        public void OnValidateIdentityThrowsOnNullGetIdCallback()
        {
            ExceptionHelper.ThrowsArgumentNull(
                () => AsyncHelper.RunSync(() => SecurityStampValidator.OnValidateIdentity<UserManager<IdentityUser>, IdentityUser, string>(TimeSpan.Zero, SignIn, null)
                    .Invoke(null)), "getUserIdCallback");
        }

        [Fact]
        public async Task OnValidateIdentityTest()
        {
            var owinContext = GlobalHelpers.CreateContext();
            await CreateManager(owinContext);
            var manager = owinContext.GetUserManager<UserManager<IdentityUser>>();
            var user = new IdentityUser("test");
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            var id = await SignIn(manager, user);
            var ticket = GlobalHelpers.CreateAuthenticationTicket(id, new AuthenticationProperties { IssuedUtc = DateTimeOffset.UtcNow });
            var context = GlobalHelpers.CreateCookieValidateIdentityContext(owinContext, ticket, new CookieAuthenticationOptions());
            await
                SecurityStampValidator.OnValidateIdentity<UserManager<IdentityUser>, IdentityUser>(TimeSpan.Zero, SignIn)
                    .Invoke(context);
            Assert.NotNull(context.ExtractClaimsIdentity());
            Assert.Equal(user.Id, id.GetUserId());

            // change stamp and make sure it fails
            UnitTestHelper.IsSuccess(await manager.UpdateSecurityStampAsync(user.Id));
            await
                SecurityStampValidator.OnValidateIdentity<UserManager<IdentityUser>, IdentityUser>(TimeSpan.Zero, SignIn)
                    .Invoke(context);
            Assert.Null(context.ExtractClaimsIdentity());
        }

        [Fact]
        public async Task OnValidateRejectsUnknownUserIdentityTest()
        {
            var owinContext = GlobalHelpers.CreateContext();
            await CreateManager(owinContext);
            var manager = owinContext.GetUserManager<UserManager<IdentityUser>>();
            var user = new IdentityUser("test");
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            var id = await SignIn(manager, user);
            UnitTestHelper.IsSuccess(await manager.DeleteAsync(user));
            var ticket = GlobalHelpers.CreateAuthenticationTicket(id, new AuthenticationProperties { IssuedUtc = DateTimeOffset.UtcNow });
            var context = GlobalHelpers.CreateCookieValidateIdentityContext(owinContext, ticket, new CookieAuthenticationOptions());
            await
                SecurityStampValidator.OnValidateIdentity<UserManager<IdentityUser>, IdentityUser>(TimeSpan.Zero, SignIn)
                    .Invoke(context);
            Assert.Null(context.ExtractClaimsIdentity());
        }

        [Fact]
        public async Task OnValidateIdentityRejectsWithNoIssuedUtcTest()
        {
            var owinContext = GlobalHelpers.CreateContext();
            await CreateManager(owinContext);
            var manager = owinContext.GetUserManager<UserManager<IdentityUser>>();
            var user = new IdentityUser("test");
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            var id = await SignIn(manager, user);
            var ticket = GlobalHelpers.CreateAuthenticationTicket(id, new AuthenticationProperties());
            var context = GlobalHelpers.CreateCookieValidateIdentityContext(owinContext, ticket, new CookieAuthenticationOptions());
            await
                SecurityStampValidator.OnValidateIdentity<UserManager<IdentityUser>, IdentityUser>(TimeSpan.Zero, SignIn)
                    .Invoke(context);
            Assert.NotNull(context.ExtractClaimsIdentity());
            Assert.Equal(user.Id, id.GetUserId());

            // change stamp does fail validation when no utc
            UnitTestHelper.IsSuccess(await manager.UpdateSecurityStampAsync(user.Id));
            await
                SecurityStampValidator.OnValidateIdentity<UserManager<IdentityUser>, IdentityUser>(TimeSpan.Zero, SignIn)
                    .Invoke(context);
            Assert.Null(context.ExtractClaimsIdentity());
        }

        [Fact]
        public async Task OnValidateIdentityDoesNotRejectRightAwayTest()
        {
            var owinContext = GlobalHelpers.CreateContext();
            await CreateManager(owinContext);
            var manager = owinContext.GetUserManager<UserManager<IdentityUser>>();
            var user = new IdentityUser("test");
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            var id = await SignIn(manager, user);
            var ticket = GlobalHelpers.CreateAuthenticationTicket(id, new AuthenticationProperties { IssuedUtc = DateTimeOffset.UtcNow });
            var context = GlobalHelpers.CreateCookieValidateIdentityContext(owinContext, ticket, new CookieAuthenticationOptions());

            // change stamp does not fail validation when not enough time elapsed
            UnitTestHelper.IsSuccess(await manager.UpdateSecurityStampAsync(user.Id));
            await
                SecurityStampValidator.OnValidateIdentity<UserManager<IdentityUser>, IdentityUser>(
                    TimeSpan.FromDays(1), SignIn).Invoke(context);
            Assert.NotNull(context.ExtractClaimsIdentity());
            Assert.Equal(user.Id, id.GetUserId());
        }

        [Fact]
        public async Task OnValidateIdentityResetsContextPropertiesDatesTest()
        {
            // Arrange
            var owinContext = GlobalHelpers.CreateContext();
            await CreateManager(owinContext);
            var manager = owinContext.GetUserManager<UserManager<IdentityUser>>();
            var user = new IdentityUser(string.Format("{0}{1}", "test", new Random().Next()));
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            var id = await SignIn(manager, user);
            var ticket = GlobalHelpers.CreateAuthenticationTicket(id, new AuthenticationProperties { IssuedUtc = DateTimeOffset.UtcNow, ExpiresUtc = DateTimeOffset.UtcNow.Add(TimeSpan.FromHours(1)), IsPersistent = true });
            var context = GlobalHelpers.CreateCookieValidateIdentityContext(owinContext, ticket, new CookieAuthenticationOptions());

            await
                SecurityStampValidator.OnValidateIdentity<UserManager<IdentityUser>, IdentityUser>(
                    TimeSpan.Zero, SignIn).Invoke(context);

            // Assert
            Assert.NotNull(context.ExtractClaimsIdentity());
            Assert.NotNull(context.Properties);
            Assert.Null(context.Properties.IssuedUtc);
            Assert.Null(context.Properties.ExpiresUtc);
            Assert.True(context.Properties.IsPersistent);
        }

        private Task<ClaimsIdentity> SignIn(UserManager<IdentityUser> manager, IdentityUser user)
        {
            return manager.ClaimsIdentityFactory.CreateAsync(manager, user, DefaultAuthenticationTypes.ApplicationCookie);
        }
#if NETFRAMEWORK
        private async Task CreateManager(OwinContext context)
        {
            var options = new IdentityFactoryOptions<UserManager<IdentityUser>>
            {
                Provider = new TestProvider(),
                DataProtectionProvider = new DpapiDataProtectionProvider()
            };
            var middleware =
                new IdentityFactoryMiddleware
                    <UserManager<IdentityUser>, IdentityFactoryOptions<UserManager<IdentityUser>>>(null, options);
            await middleware.Invoke(context);
        }
#else
        private async Task CreateManager(HttpContext context)
        {
            var options = new IdentityFactoryOptions<UserManager<IdentityUser>>
            {
                Provider = new TestProvider(),
                DataProtectionProvider = new EphemeralDataProtectionProvider()
            };
            var middleware =
                new IdentityFactoryMiddleware
                    <UserManager<IdentityUser>, IdentityFactoryOptions<UserManager<IdentityUser>>>(options);
            await middleware.InvokeAsync(context, null);
        }
#endif

        private class TestProvider : IdentityFactoryProvider<UserManager<IdentityUser>>
        {
            public TestProvider()
            {
                OnCreate = ((options, context) =>
                {
                    var manager =
                        new UserManager<IdentityUser>(new UserStore<IdentityUser>(UnitTestHelper.CreateDefaultDb()));
                    manager.UserValidator = new UserValidator<IdentityUser>(manager)
                    {
                        AllowOnlyAlphanumericUserNames = true,
                        RequireUniqueEmail = false
                    };
                    if (options.DataProtectionProvider != null)
                    {
                        manager.UserTokenProvider =
                            new DataProtectorTokenProvider<IdentityUser>(
                                options.DataProtectionProvider.Create("ASP.NET Identity"));
                    }
                    return manager;
                });
                OnDispose = (options, manager) => { };
            }
        }
    }
}