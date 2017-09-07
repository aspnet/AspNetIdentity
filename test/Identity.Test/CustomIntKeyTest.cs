// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System.Data.Entity;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.DataProtection;
using Xunit;

namespace Identity.Test
{
    public class CustomIntKeyTest
    {
        [Fact]
        public async Task CustomUserIntKeyTest()
        {
            Database.SetInitializer(new DropCreateDatabaseAlways<CustomUserContext>());
            var db = new CustomUserContext();
            db.Database.Initialize(true);
            var manager = new UserManager<CustomUser, int>(new CustomUserStore(db));
            CustomUser[] users =
            {
                new CustomUser {UserName = "test"},
                new CustomUser {UserName = "test1"},
                new CustomUser {UserName = "test2"},
                new CustomUser {UserName = "test3"}
            };
            foreach (CustomUser user in users)
            {
                UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            }
            foreach (CustomUser user in users)
            {
                var u = await manager.FindByIdAsync(user.Id);
                Assert.NotNull(u);
                Assert.Equal(u.UserName, user.UserName);
            }
        }

        [Fact]
        public void EnsureDefaultSchemaWithInt()
        {
            IdentityDbContextTest.VerifyDefaultSchema(new CustomUserContext());
        }

        [Fact]
        public async Task CustomIntGetRolesForUserTest()
        {
            Database.SetInitializer(new DropCreateDatabaseAlways<CustomUserContext>());
            var db = new CustomUserContext();
            db.Database.Initialize(true);
            var userManager = new UserManager<CustomUser, int>(new CustomUserStore(db));
            var roleManager = new RoleManager<CustomRole, int>(new CustomRoleStore(db));
            CustomUser[] users =
            {
                new CustomUser("u1"), new CustomUser("u2"), new CustomUser("u3"), new CustomUser("u4")
            };
            CustomRole[] roles =
            {
                new CustomRole("r1"), new CustomRole("r2"), new CustomRole("r3"), new CustomRole("r4")
            };
            foreach (CustomUser u in users)
            {
                UnitTestHelper.IsSuccess(await userManager.CreateAsync(u));
            }
            foreach (CustomRole r in roles)
            {
                UnitTestHelper.IsSuccess(await roleManager.CreateAsync(r));
                foreach (CustomUser u in users)
                {
                    UnitTestHelper.IsSuccess(await userManager.AddToRoleAsync(u.Id, r.Name));
                    Assert.True(await userManager.IsInRoleAsync(u.Id, r.Name));
                }
                Assert.Equal(users.Length, r.Users.Count());
            }

            foreach (CustomUser u in users)
            {
                var rs = await userManager.GetRolesAsync(u.Id);
                Assert.Equal(roles.Length, rs.Count);
                foreach (CustomRole r in roles)
                {
                    Assert.True(rs.Any(role => role == r.Name));
                }
            }
        }

        [Fact]
        public async Task IntKeyConfirmEmailTest()
        {
            var manager = CreateManager();
            var user = new CustomUser("testEmailConfirm");
            Assert.False(user.EmailConfirmed);
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            var token = await manager.GenerateEmailConfirmationTokenAsync(user.Id);
            Assert.NotNull(token);
            UnitTestHelper.IsSuccess(await manager.ConfirmEmailAsync(user.Id, token));
            Assert.True(await manager.IsEmailConfirmedAsync(user.Id));
            UnitTestHelper.IsSuccess(await manager.SetEmailAsync(user.Id, null));
            Assert.False(await manager.IsEmailConfirmedAsync(user.Id));
        }

        private UserManager<CustomUser, int> CreateManager()
        {
            var options = new IdentityFactoryOptions<UserManager<CustomUser, int>>
            {
                Provider = new TestProvider(),
                DataProtectionProvider = new DpapiDataProtectionProvider()
            };
            return options.Provider.Create(options, new OwinContext());
        }

        public class CustomRole : IdentityRole<int, CustomUserRole>
        {
            public CustomRole()
            {
            }

            public CustomRole(string name)
            {
                Name = name;
            }
        }

        private class CustomRoleStore : RoleStore<CustomRole, int, CustomUserRole>
        {
            public CustomRoleStore(DbContext context)
                : base(context)
            {
            }
        }

        public class CustomUser : IdentityUser<int, CustomUserLogin, CustomUserRole, CustomUserClaim>
        {
            public CustomUser()
            {
            }

            public CustomUser(string name)
            {
                UserName = name;
            }
        }

        public class CustomUserClaim : IdentityUserClaim<int>
        {
        }

        private class CustomUserContext :
            IdentityDbContext<CustomUser, CustomRole, int, CustomUserLogin, CustomUserRole, CustomUserClaim>
        {
        }

        public class CustomUserLogin : IdentityUserLogin<int>
        {
        }

        public class CustomUserRole : IdentityUserRole<int>
        {
        }

        private class CustomUserStore :
            UserStore<CustomUser, CustomRole, int, CustomUserLogin, CustomUserRole, CustomUserClaim>
        {
            public CustomUserStore(DbContext context)
                : base(context)
            {
            }
        }

        private class TestProvider : IdentityFactoryProvider<UserManager<CustomUser, int>>
        {
            public TestProvider()
            {
                OnCreate = ((options, context) =>
                {
                    Database.SetInitializer(new DropCreateDatabaseAlways<CustomUserContext>());
                    var db = new CustomUserContext();
                    db.Database.Initialize(true);
                    var manager = new UserManager<CustomUser, int>(new CustomUserStore(db));
                    manager.UserValidator = new UserValidator<CustomUser, int>(manager)
                    {
                        AllowOnlyAlphanumericUserNames = true,
                        RequireUniqueEmail = false
                    };
                    if (options.DataProtectionProvider != null)
                    {
                        manager.UserTokenProvider =
                            new DataProtectorTokenProvider<CustomUser, int>(
                                options.DataProtectionProvider.Create("ASP.NET Identity"));
                    }
                    return manager;
                });
            }
        }
    }
}