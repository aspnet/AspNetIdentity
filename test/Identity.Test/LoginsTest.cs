// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Xunit;

namespace Identity.Test
{
    public class LoginsTest
    {
        [Fact]
        public async Task LinkUnlinkDeletesTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var mgr = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            var user = new IdentityUser("linkunlinktest");
            UnitTestHelper.IsSuccess(await mgr.CreateAsync(user));
            var userLogin1 = new UserLoginInfo("provider1", "p1-1");
            var userLogin2 = new UserLoginInfo("provider2", "p2-1");
            Assert.Equal(0, (await mgr.GetLoginsAsync(user.Id)).Count);
            UnitTestHelper.IsSuccess(await mgr.AddLoginAsync(user.Id, userLogin1));
            Assert.Equal(1, user.Logins.Count(l => l.ProviderKey == "p1-1"));
            Assert.Equal(1, (await mgr.GetLoginsAsync(user.Id)).Count);
            UnitTestHelper.IsSuccess(await mgr.AddLoginAsync(user.Id, userLogin2));
            Assert.Equal(1, user.Logins.Count(l => l.ProviderKey == "p2-1"));
            Assert.Equal(2, (await mgr.GetLoginsAsync(user.Id)).Count);
            UnitTestHelper.IsSuccess(await mgr.RemoveLoginAsync(user.Id, userLogin1));
            Assert.Equal(0, user.Logins.Count(l => l.ProviderKey == "p1-1"));
            Assert.Equal(1, user.Logins.Count(l => l.ProviderKey == "p2-1"));
            Assert.Equal(1, (await mgr.GetLoginsAsync(user.Id)).Count());
            UnitTestHelper.IsSuccess(await mgr.RemoveLoginAsync(user.Id, userLogin2));
            Assert.Equal(0, (await mgr.GetLoginsAsync(user.Id)).Count);
            Assert.Equal(0, db.Set<IdentityUserLogin>().Count());
        }

        [Fact]
        public async Task AddDuplicateLoginFailsTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var mgr = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            var user = new IdentityUser("dupeLogintest");
            UnitTestHelper.IsSuccess(await mgr.CreateAsync(user));
            var userLogin1 = new UserLoginInfo("provider1", "p1-1");
            UnitTestHelper.IsSuccess(await mgr.AddLoginAsync(user.Id, userLogin1));
            UnitTestHelper.IsFailure(await mgr.AddLoginAsync(user.Id, userLogin1));
        }


        //[Fact]
        //public async Task RemoveUnknownLoginFailsTest() {
        //    var store = new UserManager<IdentityUser>(new UserStore<IdentityUser>(UnitTestHelper.CreateDefaultDb()));
        //    UnitTestHelper.IsFailure(await store.Users.RemoveLoginAsync("bogus", "whatever", "ignored"));
        //}

        [Fact]
        public async Task AddLoginNullLoginFailsTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var manager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            var user = new IdentityUser("Hao");
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => manager.AddLoginAsync(user.Id, null)),
                "login");
        }
    }
}