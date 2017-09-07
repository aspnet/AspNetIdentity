// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Xunit;

namespace Identity.Test
{
    public class UserClaimsTest
    {
        [Fact]
        public async Task AddRemoveUserClaimTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var store = new UserStore<IdentityUser>(db);
            ;
            var user = new IdentityUser("ClaimsAddRemove");
            await store.CreateAsync(user);
            Claim[] claims = {new Claim("c", "v"), new Claim("c2", "v2"), new Claim("c2", "v3")};
            foreach (Claim c in claims)
            {
                await store.AddClaimAsync(user, c);
            }
            await store.UpdateAsync(user);
            var userClaims = await store.GetClaimsAsync(user);
            Assert.Equal(3, userClaims.Count);
            await store.RemoveClaimAsync(user, claims[0]);
            Assert.Equal(3, userClaims.Count); // No effect until save changes
            db.SaveChanges();
            userClaims = await store.GetClaimsAsync(user);
            Assert.Equal(2, userClaims.Count);
            await store.RemoveClaimAsync(user, claims[1]);
            Assert.Equal(2, userClaims.Count); // No effect until save changes
            db.SaveChanges();
            userClaims = await store.GetClaimsAsync(user);
            Assert.Equal(1, userClaims.Count);
            await store.RemoveClaimAsync(user, claims[2]);
            Assert.Equal(1, userClaims.Count); // No effect until save changes
            db.SaveChanges();
            userClaims = await store.GetClaimsAsync(user);
            Assert.Equal(0, userClaims.Count);
            //Assert.Equal(0, user.Claims.Count);
        }

        [Fact]
        public async Task GetUserClaimTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var manager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            var user = new IdentityUser("u1");
            var result = await manager.CreateAsync(user);
            UnitTestHelper.IsSuccess(result);
            Assert.NotNull(user);
            var claims = new[]
            {
                new Claim("c1", "v1"),
                new Claim("c2", "v2"),
                new Claim("c3", "v3")
            };
            foreach (Claim c in claims)
            {
                UnitTestHelper.IsSuccess(await manager.AddClaimAsync(user.Id, c));
            }
            var userClaims = new List<Claim>(await manager.GetClaimsAsync(user.Id));
            Assert.Equal(3, userClaims.Count);
            foreach (Claim c in claims)
            {
                Assert.True(userClaims.Exists(u => u.Type == c.Type && u.Value == c.Value));
            }
        }

        [Fact]
        public void GetUserClaimSyncTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var manager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            var user = new IdentityUser("u1");
            var result = manager.Create(user);
            UnitTestHelper.IsSuccess(result);
            Assert.NotNull(user);
            var claims = new[]
            {
                new Claim("c1", "v1"),
                new Claim("c2", "v2"),
                new Claim("c3", "v3")
            };
            foreach (Claim c in claims)
            {
                UnitTestHelper.IsSuccess(manager.AddClaim(user.Id, c));
            }
            var userClaims = new List<Claim>(manager.GetClaims(user.Id));
            Assert.Equal(3, userClaims.Count);
            foreach (Claim c in claims)
            {
                Assert.True(userClaims.Exists(u => u.Type == c.Type && u.Value == c.Value));
            }
        }

        [Fact]
        public void RemoveUserClaimSyncTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var manager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            var user = new IdentityUser("u1");
            var result = manager.Create(user);
            Assert.NotNull(user);
            var claims = new[]
            {
                new Claim("c1", "v1"),
                new Claim("c2", "v2"),
                new Claim("c3", "v3")
            };
            foreach (Claim c in claims)
            {
                UnitTestHelper.IsSuccess(manager.AddClaim(user.Id, c));
            }

            var userClaims = new List<Claim>(manager.GetClaims(user.Id));
            Assert.Equal(3, userClaims.Count);
            foreach (Claim c in claims)
            {
                Assert.True(userClaims.Exists(u => u.Type == c.Type && u.Value == c.Value));
                UnitTestHelper.IsSuccess(manager.RemoveClaim(user.Id, c));
            }
            var cs = manager.GetClaims(user.Id);
            Assert.Equal(0, cs.Count());
            Assert.Equal(0, db.Set<IdentityUserClaim>().Count());
        }

        [Fact]
        public async Task RemoveUserClaimTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var manager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            var user = new IdentityUser("u1");
            var result = await manager.CreateAsync(user);
            Assert.NotNull(user);
            var claims = new[]
            {
                new Claim("c1", "v1"),
                new Claim("c2", "v2"),
                new Claim("c3", "v3")
            };
            foreach (Claim c in claims)
            {
                UnitTestHelper.IsSuccess(await manager.AddClaimAsync(user.Id, c));
            }

            var userClaims = new List<Claim>(await manager.GetClaimsAsync(user.Id));
            Assert.Equal(3, userClaims.Count);
            foreach (Claim c in claims)
            {
                Assert.True(userClaims.Exists(u => u.Type == c.Type && u.Value == c.Value));
                UnitTestHelper.IsSuccess(await manager.RemoveClaimAsync(user.Id, c));
            }
            var cs = await manager.GetClaimsAsync(user.Id);
            Assert.Equal(0, cs.Count());
            Assert.Equal(0, db.Set<IdentityUserClaim>().Count());
        }

        [Fact]
        public async Task DupeUserClaimTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var manager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            var user = new IdentityUser("u1");
            var result = await manager.CreateAsync(user);
            Assert.NotNull(user);
            var claims = new[]
            {
                new Claim("c1", "v1"),
                new Claim("c2", "v2"),
                new Claim("c3", "v3")
            };
            foreach (Claim c in claims)
            {
                // Add dupes
                UnitTestHelper.IsSuccess(await manager.AddClaimAsync(user.Id, c));
                UnitTestHelper.IsSuccess(await manager.AddClaimAsync(user.Id, c));
            }

            var userClaims = new List<Claim>(await manager.GetClaimsAsync(user.Id));
            Assert.Equal(6, userClaims.Count);
            var currentExpected = 6;
            foreach (Claim c in claims)
            {
                Assert.True(userClaims.Exists(u => u.Type == c.Type && u.Value == c.Value));
                UnitTestHelper.IsSuccess(await manager.RemoveClaimAsync(user.Id, c));
                var cs = await manager.GetClaimsAsync(user.Id);
                currentExpected -= 2;
                Assert.Equal(currentExpected, cs.Count());
                Assert.Equal(currentExpected, db.Set<IdentityUserClaim>().Count());
            }
        }
    }
}