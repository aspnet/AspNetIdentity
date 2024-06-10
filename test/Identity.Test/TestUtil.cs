// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Data.Entity;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;

#if NETFRAMEWORK
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.DataProtection;
#else 
using Microsoft.AspNet.Identity.AspNetCore;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
#endif 

namespace Identity.Test
{
    public static class TestUtil
    {
        public static void SetupDatabase<TDbContext>(string dataDirectory) where TDbContext : DbContext
        {
            AppDomain.CurrentDomain.SetData("DataDirectory", dataDirectory);
            Database.SetInitializer(new DropCreateDatabaseAlways<TDbContext>());
        }

        public static UserManager<IdentityUser> CreateManager(DbContext db)
        {
            var options = new IdentityFactoryOptions<UserManager<IdentityUser>>
            {
                Provider = new TestProvider(db),
                DataProtectionProvider = GlobalHelpers.CreateDataProtectionProvider()
            };
            return options.Provider.Create(options, GlobalHelpers.CreateContext());
        }

        public static UserManager<IdentityUser> CreateManager()
        {
            return CreateManager(UnitTestHelper.CreateDefaultDb());
        }

#if NETFRAMEWORK
        public static async Task CreateManager(OwinContext context)
        {
            var options = new IdentityFactoryOptions<UserManager<IdentityUser>>
            {
                Provider = new TestProvider(UnitTestHelper.CreateDefaultDb()),
                DataProtectionProvider = new DpapiDataProtectionProvider()
            };
            var middleware =
                new IdentityFactoryMiddleware
                    <UserManager<IdentityUser>, IdentityFactoryOptions<UserManager<IdentityUser>>>(null, options);
            await middleware.Invoke(context);
        }
#else
        public static async Task CreateManager(HttpContext context)
        {
            var options = new IdentityFactoryOptions<UserManager<IdentityUser>>
            {
                Provider = new TestProvider(UnitTestHelper.CreateDefaultDb()),
                DataProtectionProvider = new EphemeralDataProtectionProvider()
            };
            var middleware =
                new IdentityFactoryMiddleware
                    <UserManager<IdentityUser>, IdentityFactoryOptions<UserManager<IdentityUser>>>(options);
            await middleware.InvokeAsync(context, null);
        }
#endif 
    }

    public class TestProvider : IdentityFactoryProvider<UserManager<IdentityUser>>
    {
        public TestProvider(DbContext db)
        {
            OnCreate = ((options, context) =>
            {
                var manager =
                    new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
                manager.UserValidator = new UserValidator<IdentityUser>(manager)
                {
                    AllowOnlyAlphanumericUserNames = true,
                    RequireUniqueEmail = false
                };
                manager.EmailService = new TestMessageService();
                manager.SmsService = new TestMessageService();
                if (options.DataProtectionProvider != null)
                {
                    manager.UserTokenProvider =
                        new DataProtectorTokenProvider<IdentityUser>(
                            options.DataProtectionProvider.Create("ASP.NET Identity"));
                }
                return manager;
            });
        }
    }

    public class TestMessageService : IIdentityMessageService
    {
        public IdentityMessage Message { get; set; }

        public Task SendAsync(IdentityMessage message)
        {
            Message = message;
            return Task.FromResult(0);
        }
    }
}