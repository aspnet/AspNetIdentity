// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Data.Entity.Validation;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Xunit;

namespace Identity.Test
{
    public class UserStoreTest
    {
        [Fact]
        public void AddUserWithNoUserNameFailsTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var store = new UserStore<IdentityUser>(db);
            Assert.Throws<DbEntityValidationException>(
                () => AsyncHelper.RunSync(() => store.CreateAsync(new IdentityUser())));
        }

        [Fact]
        public async Task CanDisableAutoSaveChangesTest()
        {
            var db = new NoopIdentityDbContext();
            var store = new UserStore<IdentityUser>(db);
            store.AutoSaveChanges = false;
            var user = new IdentityUser("test");
            await store.CreateAsync(user);
            Assert.False(db.SaveChangesCalled);
        }

        [Fact]
        public async Task CreateAutoSavesTest()
        {
            var db = new NoopIdentityDbContext();
            db.Configuration.ValidateOnSaveEnabled = false;
            var store = new UserStore<IdentityUser>(db);
            var user = new IdentityUser("test");
            await store.CreateAsync(user);
            Assert.True(db.SaveChangesCalled);
        }

        [Fact]
        public async Task UpdateAutoSavesTest()
        {
            var db = new NoopIdentityDbContext();
            var store = new UserStore<IdentityUser>(db);
            var user = new IdentityUser("test");
            await store.UpdateAsync(user);
            Assert.True(db.SaveChangesCalled);
        }

        [Fact]
        public async Task AddDupeUserIdWithStoreFailsTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var store = new UserStore<IdentityUser>(db);
            var user = new IdentityUser("dupemgmt");
            await store.CreateAsync(user);
            var u2 = new IdentityUser {Id = user.Id, UserName = "User"};
            try
            {
                await store.CreateAsync(u2);
                Assert.False(true);
            }
            catch (Exception e)
            {
                Assert.True(e.InnerException.InnerException.Message.Contains("duplicate key"));
            }
        }

        [Fact]
        public void UserStoreMethodsThrowWhenDisposedTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var store = new UserStore<IdentityUser>(db);
            store.Dispose();
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => store.AddClaimAsync(null, null)));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => store.AddLoginAsync(null, null)));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => store.AddToRoleAsync(null, null)));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => store.GetClaimsAsync(null)));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => store.GetLoginsAsync(null)));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => store.GetRolesAsync(null)));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => store.IsInRoleAsync(null, null)));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => store.RemoveClaimAsync(null, null)));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => store.RemoveLoginAsync(null, null)));
            Assert.Throws<ObjectDisposedException>(
                () => AsyncHelper.RunSync(() => store.RemoveFromRoleAsync(null, null)));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => store.RemoveClaimAsync(null, null)));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => store.FindAsync(null)));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => store.FindByIdAsync(null)));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => store.FindByNameAsync(null)));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => store.UpdateAsync(null)));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => store.DeleteAsync(null)));
            Assert.Throws<ObjectDisposedException>(
                () => AsyncHelper.RunSync(() => store.SetEmailConfirmedAsync(null, true)));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => store.GetEmailConfirmedAsync(null)));
            Assert.Throws<ObjectDisposedException>(
                () => AsyncHelper.RunSync(() => store.SetPhoneNumberConfirmedAsync(null, true)));
            Assert.Throws<ObjectDisposedException>(
                () => AsyncHelper.RunSync(() => store.GetPhoneNumberConfirmedAsync(null)));
        }

        [Fact]
        public void UserStorePublicNullCheckTest()
        {
            var store = new UserStore<IdentityUser>();
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => store.CreateAsync(null)), "user");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => store.UpdateAsync(null)), "user");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => store.DeleteAsync(null)), "user");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => store.AddClaimAsync(null, null)), "user");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => store.RemoveClaimAsync(null, null)),
                "user");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => store.GetClaimsAsync(null)), "user");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => store.GetLoginsAsync(null)), "user");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => store.GetRolesAsync(null)), "user");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => store.AddLoginAsync(null, null)), "user");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => store.RemoveLoginAsync(null, null)),
                "user");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => store.AddToRoleAsync(null, null)), "user");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => store.RemoveFromRoleAsync(null, null)),
                "user");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => store.IsInRoleAsync(null, null)), "user");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => store.GetPasswordHashAsync(null)), "user");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => store.SetPasswordHashAsync(null, null)),
                "user");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => store.GetSecurityStampAsync(null)),
                "user");
            ExceptionHelper.ThrowsArgumentNull(
                () => AsyncHelper.RunSync(() => store.SetSecurityStampAsync(null, null)), "user");
            ExceptionHelper.ThrowsArgumentNull(
                () => AsyncHelper.RunSync(() => store.AddClaimAsync(new IdentityUser("fake"), null)), "claim");
            ExceptionHelper.ThrowsArgumentNull(
                () => AsyncHelper.RunSync(() => store.RemoveClaimAsync(new IdentityUser("fake"), null)), "claim");
            ExceptionHelper.ThrowsArgumentNull(
                () => AsyncHelper.RunSync(() => store.AddLoginAsync(new IdentityUser("fake"), null)), "login");
            ExceptionHelper.ThrowsArgumentNull(
                () => AsyncHelper.RunSync(() => store.RemoveLoginAsync(new IdentityUser("fake"), null)), "login");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => store.FindAsync(null)), "login");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => store.GetEmailConfirmedAsync(null)),
                "user");
            ExceptionHelper.ThrowsArgumentNull(
                () => AsyncHelper.RunSync(() => store.SetEmailConfirmedAsync(null, true)), "user");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => store.GetEmailAsync(null)), "user");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => store.SetEmailAsync(null, null)), "user");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => store.GetPhoneNumberAsync(null)), "user");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => store.SetPhoneNumberAsync(null, null)),
                "user");
            ExceptionHelper.ThrowsArgumentNull(
                () => AsyncHelper.RunSync(() => store.GetPhoneNumberConfirmedAsync(null)), "user");
            ExceptionHelper.ThrowsArgumentNull(
                () => AsyncHelper.RunSync(() => store.SetPhoneNumberConfirmedAsync(null, true)), "user");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => store.GetTwoFactorEnabledAsync(null)),
                "user");
            ExceptionHelper.ThrowsArgumentNull(
                () => AsyncHelper.RunSync(() => store.SetTwoFactorEnabledAsync(null, true)), "user");
            ExceptionHelper.ThrowsArgumentNullOrEmpty(
                () => AsyncHelper.RunSync(() => store.AddToRoleAsync(new IdentityUser("fake"), null)), "roleName");
            ExceptionHelper.ThrowsArgumentNullOrEmpty(
                () => AsyncHelper.RunSync(() => store.RemoveFromRoleAsync(new IdentityUser("fake"), null)), "roleName");
            ExceptionHelper.ThrowsArgumentNullOrEmpty(
                () => AsyncHelper.RunSync(() => store.IsInRoleAsync(new IdentityUser("fake"), null)), "roleName");
        }

        [Fact]
        public async Task AddDupeUserNameWithStoreFailsTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var mgr = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            var store = new UserStore<IdentityUser>(db);
            var user = new IdentityUser("dupe");
            UnitTestHelper.IsSuccess(await mgr.CreateAsync(user));
            var u2 = new IdentityUser("DUPe");
            Assert.Throws<DbEntityValidationException>(() => AsyncHelper.RunSync(() => store.CreateAsync(u2)));
        }

        [Fact]
        public async Task AddDupeEmailWithStoreFailsTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            db.RequireUniqueEmail = true;
            var mgr = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            var store = new UserStore<IdentityUser>(db);
            var user = new IdentityUser("u1") {Email = "email"};
            UnitTestHelper.IsSuccess(await mgr.CreateAsync(user));
            var u2 = new IdentityUser("u2") {Email = "email"};
            Assert.Throws<DbEntityValidationException>(() => AsyncHelper.RunSync(() => store.CreateAsync(u2)));
        }

        [Fact]
        public async Task DeleteUserTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var store = new UserStore<IdentityUser>(db);
            var mgmt = new IdentityUser("deletemgmttest");
            await store.CreateAsync(mgmt);
            Assert.NotNull(await store.FindByIdAsync(mgmt.Id));
            await store.DeleteAsync(mgmt);
            Assert.Null(await store.FindByIdAsync(mgmt.Id));
        }

        //private class MyUser : IUser {
        //    public string Id { get; set; }
        //    public bool DisableSignIn { get; set; }
        //    public string PasswordHash { get; set; }
        //    public string UserName { get; set; }
        //    public string SecurityToken { get; set; }
        //    public DateTimeOffset SecurityTokenValidUntil { get; set; }
        //}

        //[Fact]
        //public void CreateWrongUserTypeFailsTest() {
        //    var db = UnitTestHelper.CreateDefaultDb();
        //    var store = new UserStore<IdentityUser>(db);
        //    ExceptionHelper.ExpectArgumentException(() => AsyncHelper.RunSync(() => store.InsertAsync(new MyUser())), "Incorrect type, expected type of User.\r\nParameter name: entity", "entity");
        //}

        //[Fact]
        //public void UpdateWrongUserTypeFailsTest() {
        //    var db = UnitTestHelper.CreateDefaultDb();
        //    var store = new UserStore<IdentityUser>(db);
        //    ExceptionHelper.ExpectArgumentException(() => AsyncHelper.RunSync(() => store.UpdateAsync(new MyUser())), "Incorrect type, expected type of User.\r\nParameter name: entity", "entity");
        //}

        //[Fact]
        //public void InsertNullUserFailsTest() {
        //    var db = UnitTestHelper.CreateDefaultDb();
        //    var store = new UserStore<IdentityUser>(db);
        //    ExceptionHelper.ExpectArgumentNullException(() => AsyncHelper.RunSync(() => store.InsertAsync(null)), "user");
        //}

        [Fact]
        public async Task CreateLoadDeleteUserTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var store = new UserStore<IdentityUser>(db);
            var user = new IdentityUser("Test");
            Assert.Null(await store.FindByIdAsync(user.Id));
            await store.CreateAsync(user);
            var loadUser = await store.FindByIdAsync(user.Id);
            Assert.NotNull(loadUser);

            Assert.Equal(user.Id, loadUser.Id);
            await store.DeleteAsync(loadUser);
            loadUser = await store.FindByIdAsync(user.Id);
            Assert.Null(loadUser);
        }

        [Fact]
        public async Task FindByUserName()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var store = new UserStore<IdentityUser>(db);
            var user = new IdentityUser("Hao");
            await store.CreateAsync(user);
            var found = await store.FindByNameAsync("hao");
            Assert.NotNull(found);
            Assert.Equal(user.Id, found.Id);

            found = await store.FindByNameAsync("HAO");
            Assert.NotNull(found);
            Assert.Equal(user.Id, found.Id);

            found = await store.FindByNameAsync("Hao");
            Assert.NotNull(found);
            Assert.Equal(user.Id, found.Id);
        }

        [Fact]
        public async Task GetAllUsersTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var store = new UserStore<IdentityUser>(db);
            var users = new[]
            {
                new IdentityUser("user1"),
                new IdentityUser("user2"),
                new IdentityUser("user3")
            };
            foreach (IdentityUser u in users)
            {
                await store.CreateAsync(u);
            }
            IQueryable<IUser> usersQ = store.Users;
            Assert.Equal(3, usersQ.Count());
            Assert.NotNull(usersQ.Where(u => u.UserName == "user1").FirstOrDefault());
            Assert.NotNull(usersQ.Where(u => u.UserName == "user2").FirstOrDefault());
            Assert.NotNull(usersQ.Where(u => u.UserName == "user3").FirstOrDefault());
            Assert.Null(usersQ.Where(u => u.UserName == "bogus").FirstOrDefault());
        }

        private class NoopIdentityDbContext : IdentityDbContext
        {
            public bool SaveChangesCalled { get; set; }

            public override Task<int> SaveChangesAsync(CancellationToken token)
            {
                SaveChangesCalled = true;
                return Task.FromResult(0);
            }
        }
    }
}