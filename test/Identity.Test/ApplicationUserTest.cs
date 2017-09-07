// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System.Data.Entity;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.DataProtection;
using Xunit;

namespace Identity.Test
{
    public class ApplicationUserTest
    {
        private async Task CreateManager(OwinContext context)
        {
            var options = new IdentityFactoryOptions<ApplicationUserManager>
            {
                DataProtectionProvider = new DpapiDataProtectionProvider(),
                Provider = new IdentityFactoryProvider<ApplicationUserManager>
                {
                    OnCreate = (o, c) => ApplicationUserManager.Create(o, c)
                }
            };
            var middleware =
                new IdentityFactoryMiddleware<ApplicationUserManager, IdentityFactoryOptions<ApplicationUserManager>>(
                    null, options);
            var dbMiddle =
                new IdentityFactoryMiddleware<ApplicationDbContext, IdentityFactoryOptions<ApplicationDbContext>>(
                    middleware,
                    new IdentityFactoryOptions<ApplicationDbContext>
                    {
                        Provider = new IdentityFactoryProvider<ApplicationDbContext>
                        {
                            OnCreate = (o, c) => CreateDb()
                        }
                    });
            await dbMiddle.Invoke(context);
        }

        [Fact]
        public void EnsureDefaultSchemaWithApplicationUser()
        {
            IdentityDbContextTest.VerifyDefaultSchema(CreateDb());
        }

        [Fact]
        public async Task ApplicationUserCreateTest()
        {
            var owinContext = new OwinContext();
            await CreateManager(owinContext);
            var manager = owinContext.GetUserManager<ApplicationUserManager>();
            ApplicationUser[] users =
            {
                new ApplicationUser {UserName = "test", Email = "test@test.com"},
                new ApplicationUser {UserName = "test1", Email = "test1@test.com"},
                new ApplicationUser {UserName = "test2", Email = "test2@test.com"},
                new ApplicationUser {UserName = "test3", Email = "test3@test.com"}
            };
            foreach (ApplicationUser user in users)
            {
                UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            }
            foreach (ApplicationUser user in users)
            {
                var u = await manager.FindByIdAsync(user.Id);
                Assert.NotNull(u);
                Assert.Equal(u.UserName, user.UserName);
            }
        }

        private static ApplicationDbContext CreateDb()
        {
            Database.SetInitializer(new DropCreateDatabaseAlways<ApplicationDbContext>());
            var db = ApplicationDbContext.Create();
            db.Database.Initialize(true);
            return db;
        }

        [Fact]
        public async Task ApplicationUserGetRolesForUserTest()
        {
            var db = CreateDb();
            var userManager = new ApplicationUserManager(new UserStore<ApplicationUser>(db));
            var roleManager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(db));
            ApplicationUser[] users =
            {
                new ApplicationUser("u1"), new ApplicationUser("u2"), new ApplicationUser("u3"),
                new ApplicationUser("u4")
            };
            IdentityRole[] roles =
            {
                new IdentityRole("r1"), new IdentityRole("r2"), new IdentityRole("r3"),
                new IdentityRole("r4")
            };
            foreach (ApplicationUser u in users)
            {
                UnitTestHelper.IsSuccess(await userManager.CreateAsync(u));
            }
            foreach (IdentityRole r in roles)
            {
                UnitTestHelper.IsSuccess(await roleManager.CreateAsync(r));
                foreach (ApplicationUser u in users)
                {
                    UnitTestHelper.IsSuccess(await userManager.AddToRoleAsync(u.Id, r.Name));
                    Assert.True(await userManager.IsInRoleAsync(u.Id, r.Name));
                }
                Assert.Equal(users.Length, r.Users.Count());
            }

            foreach (ApplicationUser u in users)
            {
                var rs = await userManager.GetRolesAsync(u.Id);
                Assert.Equal(roles.Length, rs.Count);
                foreach (IdentityRole r in roles)
                {
                    Assert.True(rs.Any(role => role == r.Name));
                }
            }
        }

        public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
        {
            public ApplicationDbContext() : base("DefaultConnection", false)
            {
            }

            public static ApplicationDbContext Create()
            {
                return new ApplicationDbContext();
            }
        }

        public class ApplicationUser : IdentityUser
        {
            public ApplicationUser()
            {
            }

            public ApplicationUser(string name) : base(name)
            {
            }

            public Task<ClaimsIdentity> GenerateUserIdentityAsync(ApplicationUserManager manager)
            {
                return Task.FromResult(GenerateUserIdentity(manager));
            }

            public ClaimsIdentity GenerateUserIdentity(ApplicationUserManager manager)
            {
                // Note the authenticationType must match the one defined in CookieAuthenticationOptions.AuthenticationType
                var userIdentity = manager.CreateIdentity(this, DefaultAuthenticationTypes.ApplicationCookie);
                // Add custom user claims here
                return userIdentity;
            }
        }

        public class ApplicationUserManager : UserManager<ApplicationUser>
        {
            // Configure the application user manager
            public ApplicationUserManager(IUserStore<ApplicationUser> store)
                : base(store)
            {
            }

            public static ApplicationUserManager Create(IdentityFactoryOptions<ApplicationUserManager> options,
                IOwinContext context)
            {
                var manager =
                    new ApplicationUserManager(new UserStore<ApplicationUser>(context.Get<ApplicationDbContext>()));
                manager.UserValidator = new UserValidator<ApplicationUser>(manager)
                {
                    AllowOnlyAlphanumericUserNames = false,
                    RequireUniqueEmail = true
                };
                manager.PasswordValidator = new MinimumLengthValidator(6);
                manager.RegisterTwoFactorProvider("PhoneCode", new PhoneNumberTokenProvider<ApplicationUser>
                {
                    MessageFormat = "Your security code is: {0}"
                });
                manager.RegisterTwoFactorProvider("EmailCode", new EmailTokenProvider<ApplicationUser>
                {
                    Subject = "SecurityCode",
                    BodyFormat = "Your security code is {0}"
                });
                manager.EmailService = new EmailService();
                manager.SmsService = new SMSService();
                var dataProtectionProvider = options.DataProtectionProvider;
                if (dataProtectionProvider != null)
                {
                    manager.UserTokenProvider =
                        new DataProtectorTokenProvider<ApplicationUser>(dataProtectionProvider.Create("ASP.NET Identity"));
                }
                return manager;
            }
        }

        public class EmailService : IIdentityMessageService
        {
            public Task SendAsync(IdentityMessage message)
            {
                // Plug in your email service to actually send an email here
                return Task.FromResult(0);
            }
        }

        public class SMSService : IIdentityMessageService
        {
            public Task SendAsync(IdentityMessage message)
            {
                // Plug in your sms service to actually send an text here
                return Task.FromResult(0);
            }
        }
    }
}