// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Xunit;

namespace Identity.Test
{
    public class ClaimsIdentityFactoryTest
    {
        [Fact]
        public void CreateIdentityNullCheckTest()
        {
            var factory = new ClaimsIdentityFactory<IdentityUser>();
            var manager = new UserManager<IdentityUser>(new UserStore<IdentityUser>());
            ExceptionHelper.ThrowsArgumentNull(
                () => AsyncHelper.RunSync(() => factory.CreateAsync(null, null, "whatever")), "manager");
            ExceptionHelper.ThrowsArgumentNull(
                () => AsyncHelper.RunSync(() => factory.CreateAsync(manager, null, "whatever")), "user");
            ExceptionHelper.ThrowsArgumentNull(
                () => AsyncHelper.RunSync(() => factory.CreateAsync(manager, new IdentityUser(), null)), "value");
            ExceptionHelper.ThrowsArgumentNull(() => factory.ConvertIdToString(null), "key");
        }

        [Fact]
        public async Task ClaimsIdentityTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var manager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            var role = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(db));
            var user = new IdentityUser("Hao");
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            UnitTestHelper.IsSuccess(await role.CreateAsync(new IdentityRole("Admin")));
            UnitTestHelper.IsSuccess(await role.CreateAsync(new IdentityRole("Local")));
            UnitTestHelper.IsSuccess(await manager.AddToRoleAsync(user.Id, "Admin"));
            UnitTestHelper.IsSuccess(await manager.AddToRoleAsync(user.Id, "Local"));
            Claim[] userClaims =
            {
                new Claim("Whatever", "Value"),
                new Claim("Whatever2", "Value2")
            };
            foreach (var c in userClaims)
            {
                UnitTestHelper.IsSuccess(await manager.AddClaimAsync(user.Id, c));
            }

            var identity = await manager.CreateIdentityAsync(user, "test");
            var claimsFactory = manager.ClaimsIdentityFactory as ClaimsIdentityFactory<IdentityUser, string>;
            Assert.NotNull(claimsFactory);
            var claims = identity.Claims;
            Assert.NotNull(claims);
            Assert.True(
                claims.Any(c => c.Type == claimsFactory.UserNameClaimType && c.Value == user.UserName));
            Assert.True(claims.Any(c => c.Type == claimsFactory.UserIdClaimType && c.Value == user.Id));
            Assert.True(claims.Any(c => c.Type == claimsFactory.RoleClaimType && c.Value == "Admin"));
            Assert.True(claims.Any(c => c.Type == claimsFactory.RoleClaimType && c.Value == "Local"));
            Assert.True(
                claims.Any(
                    c =>
                        c.Type == ClaimsIdentityFactory<IdentityUser>.IdentityProviderClaimType &&
                        c.Value == ClaimsIdentityFactory<IdentityUser>.DefaultIdentityProviderClaimValue));
            foreach (var cl in userClaims)
            {
                Assert.True(claims.Any(c => c.Type == cl.Type && c.Value == cl.Value));
            }
        }

        [Fact]
        public void ClaimsIdentitySyncTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var manager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            var role = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(db));
            var user = new IdentityUser("Hao");
            var claimsFactory = manager.ClaimsIdentityFactory as ClaimsIdentityFactory<IdentityUser, string>;
            Assert.NotNull(claimsFactory);
            UnitTestHelper.IsSuccess(manager.Create(user));
            UnitTestHelper.IsSuccess(role.Create(new IdentityRole("Admin")));
            UnitTestHelper.IsSuccess(role.Create(new IdentityRole("Local")));
            UnitTestHelper.IsSuccess(manager.AddToRole(user.Id, "Admin"));
            UnitTestHelper.IsSuccess(manager.AddToRole(user.Id, "Local"));
            Claim[] userClaims =
            {
                new Claim("Whatever", "Value"),
                new Claim("Whatever2", "Value2")
            };
            foreach (var c in userClaims)
            {
                UnitTestHelper.IsSuccess(manager.AddClaim(user.Id, c));
            }
            var identity = manager.CreateIdentity(user, "test");
            var claims = identity.Claims;
            Assert.NotNull(claims);
            Assert.NotNull(claims);
            Assert.True(
                claims.Any(c => c.Type == claimsFactory.UserNameClaimType && c.Value == user.UserName));
            Assert.True(claims.Any(c => c.Type == claimsFactory.UserIdClaimType && c.Value == user.Id));
            Assert.True(claims.Any(c => c.Type == claimsFactory.RoleClaimType && c.Value == "Admin"));
            Assert.True(claims.Any(c => c.Type == claimsFactory.RoleClaimType && c.Value == "Local"));
            Assert.True(
                claims.Any(
                    c =>
                        c.Type == ClaimsIdentityFactory<IdentityUser>.IdentityProviderClaimType &&
                        c.Value == ClaimsIdentityFactory<IdentityUser>.DefaultIdentityProviderClaimValue));
            foreach (var cl in userClaims)
            {
                Assert.True(claims.Any(c => c.Type == cl.Type && c.Value == cl.Value));
            }
        }
    }
}