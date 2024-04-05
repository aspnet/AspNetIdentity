// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Data.Entity;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;

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
            var manager =
                    new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            manager.UserValidator = new UserValidator<IdentityUser>(manager)
            {
                AllowOnlyAlphanumericUserNames = true,
                RequireUniqueEmail = false
            };
            manager.EmailService = new TestMessageService();
            manager.SmsService = new TestMessageService();
            //manager.UserTokenProvider =
            //    new DataProtectorTokenProvider<IdentityUser>(
            //        options.DataProtectionProvider.Create("ASP.NET Identity"));
            return manager;
        }

        public static UserManager<IdentityUser> CreateManager()
        {
            return CreateManager(UnitTestHelper.CreateDefaultDb());
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