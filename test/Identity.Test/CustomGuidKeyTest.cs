// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Data.Entity;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.DataProtection;
using Xunit;

namespace Identity.Test
{
    public class CustomGuidKeyTest
    {
        [Fact]
        public void EnsureDefaultSchemaWithInt()
        {
            IdentityDbContextTest.VerifyDefaultSchema(GuidUserContext.Create());
        }

        [Fact]
        public async Task CustomUserGuidKeyTest()
        {
            var manager = new UserManager<GuidUser, Guid>(new GuidUserStore(GuidUserContext.Create()));
            GuidUser[] users =
            {
                new GuidUser {UserName = "test"},
                new GuidUser {UserName = "test1"},
                new GuidUser {UserName = "test2"},
                new GuidUser {UserName = "test3"}
            };
            foreach (GuidUser user in users)
            {
                UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            }
            foreach (GuidUser user in users)
            {
                var u = await manager.FindByIdAsync(user.Id);
                Assert.NotNull(u);
                Assert.Equal(u.UserName, user.UserName);
            }
        }

        [Fact]
        public async Task CustomGuidGetRolesForUserTest()
        {
            var db = GuidUserContext.Create();
            var userManager = new UserManager<GuidUser, Guid>(new GuidUserStore(db));
            var roleManager = new RoleManager<GuidRole, Guid>(new GuidRoleStore(db));
            GuidUser[] users = {new GuidUser("u1"), new GuidUser("u2"), new GuidUser("u3"), new GuidUser("u4")};
            GuidRole[] roles = {new GuidRole("r1"), new GuidRole("r2"), new GuidRole("r3"), new GuidRole("r4")};
            foreach (GuidUser u in users)
            {
                UnitTestHelper.IsSuccess(await userManager.CreateAsync(u));
            }
            foreach (GuidRole r in roles)
            {
                UnitTestHelper.IsSuccess(await roleManager.CreateAsync(r));
                foreach (GuidUser u in users)
                {
                    UnitTestHelper.IsSuccess(await userManager.AddToRoleAsync(u.Id, r.Name));
                    Assert.True(await userManager.IsInRoleAsync(u.Id, r.Name));
                }
                Assert.Equal(users.Length, r.Users.Count());
            }

            foreach (GuidUser u in users)
            {
                var rs = await userManager.GetRolesAsync(u.Id);
                Assert.Equal(roles.Length, rs.Count);
                foreach (GuidRole r in roles)
                {
                    Assert.True(rs.Any(role => role == r.Name));
                }
            }
        }

        [Fact]
        public async Task CustomGuidConfirmEmailTest()
        {
            var owinContext = new OwinContext();
            await CreateManager(owinContext);
            var manager = owinContext.GetUserManager<UserManager<GuidUser, Guid>>();
            var user = new GuidUser("test");
            Assert.False(user.EmailConfirmed);
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            var token = await manager.GenerateEmailConfirmationTokenAsync(user.Id);
            Assert.NotNull(token);
            UnitTestHelper.IsSuccess(await manager.ConfirmEmailAsync(user.Id, token));
            Assert.True(await manager.IsEmailConfirmedAsync(user.Id));
            UnitTestHelper.IsSuccess(await manager.SetEmailAsync(user.Id, null));
            Assert.False(await manager.IsEmailConfirmedAsync(user.Id));
        }

        [Fact]
        public async Task CustomGuidEmailTokenFactorWithFormatTest()
        {
            var owinContext = new OwinContext();
            await CreateManager(owinContext);
            var manager = owinContext.GetUserManager<UserManager<GuidUser, Guid>>();
            var messageService = new TestMessageService();
            manager.EmailService = messageService;
            var factorId = "EmailCode";
            manager.RegisterTwoFactorProvider(factorId, new EmailTokenProvider<GuidUser, Guid>
            {
                Subject = "Security Code",
                BodyFormat = "Your code is: {0}"
            });
            var user = new GuidUser("EmailCodeTest");
            user.Email = "foo@foo.com";
            var password = "password";
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user, password));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = await manager.GenerateTwoFactorTokenAsync(user.Id, factorId);
            Assert.NotNull(token);
            Assert.Null(messageService.Message);
            await manager.NotifyTwoFactorTokenAsync(user.Id, factorId, token);
            Assert.NotNull(messageService.Message);
            Assert.Equal("Security Code", messageService.Message.Subject);
            Assert.Equal("Your code is: " + token, messageService.Message.Body);
            Assert.True(await manager.VerifyTwoFactorTokenAsync(user.Id, factorId, token));
        }


        [Fact]
        public async Task OnValidateIdentityWithGuidTest()
        {
            var owinContext = new OwinContext();
            await CreateManager(owinContext);
            var manager = owinContext.GetUserManager<UserManager<GuidUser, Guid>>();
            var user = new GuidUser {UserName = "test"};
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            var id = await SignIn(manager, user);
            var ticket = new AuthenticationTicket(id, new AuthenticationProperties {IssuedUtc = DateTimeOffset.UtcNow});
            var context = new CookieValidateIdentityContext(owinContext, ticket, new CookieAuthenticationOptions());
            await
                SecurityStampValidator.OnValidateIdentity<UserManager<GuidUser, Guid>, GuidUser, Guid>(TimeSpan.Zero,
                    SignIn, claimId => new Guid(claimId.GetUserId())).Invoke(context);
            Assert.NotNull(context.Identity);
            Assert.Equal(user.Id.ToString(), id.GetUserId());

            // change stamp and make sure it fails
            UnitTestHelper.IsSuccess(await manager.UpdateSecurityStampAsync(user.Id));
            await
                SecurityStampValidator.OnValidateIdentity<UserManager<GuidUser, Guid>, GuidUser, Guid>(TimeSpan.Zero,
                    SignIn, claimId => new Guid(claimId.GetUserId())).Invoke(context);
            Assert.Null(context.Identity);
        }

        private Task<ClaimsIdentity> SignIn(UserManager<GuidUser, Guid> manager, GuidUser user)
        {
            return manager.ClaimsIdentityFactory.CreateAsync(manager, user, DefaultAuthenticationTypes.ApplicationCookie);
        }

        private async Task CreateManager(OwinContext context)
        {
            var options = new IdentityFactoryOptions<UserManager<GuidUser, Guid>>
            {
                Provider = new TestProvider(),
                DataProtectionProvider = new DpapiDataProtectionProvider()
            };
            var middleware =
                new IdentityFactoryMiddleware
                    <UserManager<GuidUser, Guid>, IdentityFactoryOptions<UserManager<GuidUser, Guid>>>(null, options);
            var dbMiddle = new IdentityFactoryMiddleware<DbContext, IdentityFactoryOptions<DbContext>>(middleware,
                new IdentityFactoryOptions<DbContext>
                {
                    Provider = new IdentityFactoryProvider<DbContext>
                    {
                        OnCreate = (o, c) => GuidUserContext.Create(),
                    }
                });
            await dbMiddle.Invoke(context);
        }

        public class GuidRole : IdentityRole<Guid, GuidUserRole>
        {
            public GuidRole()
            {
                Id = Guid.NewGuid();
            }

            public GuidRole(string name) : this()
            {
                Name = name;
            }
        }

        private class GuidRoleStore : RoleStore<GuidRole, Guid, GuidUserRole>
        {
            public GuidRoleStore(DbContext context)
                : base(context)
            {
            }
        }

        public class GuidUser : IdentityUser<Guid, GuidUserLogin, GuidUserRole, GuidUserClaim>
        {
            public GuidUser()
            {
                Id = Guid.NewGuid();
            }

            public GuidUser(string name) : this()
            {
                UserName = name;
            }
        }

        public class GuidUserClaim : IdentityUserClaim<Guid>
        {
        }

        private class GuidUserContext :
            IdentityDbContext<GuidUser, GuidRole, Guid, GuidUserLogin, GuidUserRole, GuidUserClaim>
        {
            public static GuidUserContext Create()
            {
                Database.SetInitializer(new DropCreateDatabaseAlways<GuidUserContext>());
                var db = new GuidUserContext();
                db.Database.Initialize(true);
                return db;
            }
        }

        public class GuidUserLogin : IdentityUserLogin<Guid>
        {
        }

        public class GuidUserRole : IdentityUserRole<Guid>
        {
        }

        private class GuidUserStore : UserStore<GuidUser, GuidRole, Guid, GuidUserLogin, GuidUserRole, GuidUserClaim>
        {
            public GuidUserStore(DbContext context)
                : base(context)
            {
            }
        }

        private class TestProvider : IdentityFactoryProvider<UserManager<GuidUser, Guid>>
        {
            public TestProvider()
            {
                OnCreate = ((options, context) =>
                {
                    var manager = new UserManager<GuidUser, Guid>(new GuidUserStore(context.Get<DbContext>()));
                    manager.UserValidator = new UserValidator<GuidUser, Guid>(manager)
                    {
                        AllowOnlyAlphanumericUserNames = true,
                        RequireUniqueEmail = false
                    };
                    if (options.DataProtectionProvider != null)
                    {
                        manager.UserTokenProvider =
                            new DataProtectorTokenProvider<GuidUser, Guid>(
                                options.DataProtectionProvider.Create("ASP.NET Identity"));
                    }
                    return manager;
                });
            }
        }
    }
}