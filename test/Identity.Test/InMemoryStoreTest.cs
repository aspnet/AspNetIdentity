// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Xunit;

namespace Identity.Test
{
    public class InMemoryStoreTest
    {
        [Fact]
        public async Task DeleteUserTest()
        {
            var manager = CreateManager();
            var user = new InMemoryUser("Delete");
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            UnitTestHelper.IsSuccess(await manager.DeleteAsync(user));
            Assert.Null(await manager.FindByIdAsync(user.Id));
        }

        [Fact]
        public async Task CreateLocalUserTest()
        {
            var manager = CreateManager();
            const string password = "password";
            UnitTestHelper.IsSuccess(await manager.CreateAsync(new InMemoryUser("CreateLocalUserTest"), password));
            var user = await manager.FindByNameAsync("CreateLocalUserTest");
            Assert.NotNull(user);
            Assert.NotNull(user.PasswordHash);
            var logins = await manager.GetLoginsAsync(user.Id);
            Assert.NotNull(logins);
            Assert.Equal(0, logins.Count());
        }

        [Fact]
        public void CreateLocalUserTestSync()
        {
            var manager = CreateManager();
            const string password = "password";
            UnitTestHelper.IsSuccess(manager.Create(new InMemoryUser("CreateLocalUserTest"), password));
            var user = manager.FindByName("CreateLocalUserTest");
            Assert.NotNull(user);
            Assert.NotNull(user.PasswordHash);
            var logins = manager.GetLogins(user.Id);
            Assert.NotNull(logins);
            Assert.Equal(0, logins.Count());
        }

        [Fact]
        public async Task CreateUserAddLoginTest()
        {
            var manager = CreateManager();
            const string userName = "CreateExternalUserTest";
            const string provider = "ZzAuth";
            const string providerKey = "HaoKey";
            UnitTestHelper.IsSuccess(await manager.CreateAsync(new InMemoryUser(userName)));
            var user = await manager.FindByNameAsync(userName);
            var login = new UserLoginInfo(provider, providerKey);
            UnitTestHelper.IsSuccess(await manager.AddLoginAsync(user.Id, login));
            var logins = await manager.GetLoginsAsync(user.Id);
            Assert.NotNull(logins);
            Assert.Equal(1, logins.Count());
            Assert.Equal(provider, logins.First().LoginProvider);
            Assert.Equal(providerKey, logins.First().ProviderKey);
        }

        [Fact]
        public void CreateUserAddLoginSyncTest()
        {
            var manager = CreateManager();
            const string userName = "CreateExternalUserTest";
            const string provider = "ZzAuth";
            const string providerKey = "HaoKey";
            UnitTestHelper.IsSuccess(manager.Create(new InMemoryUser(userName)));
            var user = manager.FindByName(userName);
            var login = new UserLoginInfo(provider, providerKey);
            UnitTestHelper.IsSuccess(manager.AddLogin(user.Id, login));
            var logins = manager.GetLogins(user.Id);
            Assert.NotNull(logins);
            Assert.Equal(1, logins.Count());
            Assert.Equal(provider, logins.First().LoginProvider);
            Assert.Equal(providerKey, logins.First().ProviderKey);
        }

        [Fact]
        public async Task CreateUserLoginAndAddPasswordTest()
        {
            var manager = CreateManager();
            var login = new UserLoginInfo("Provider", "key");
            var user = new InMemoryUser("CreateUserLoginAddPasswordTest");
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            UnitTestHelper.IsSuccess(await manager.AddLoginAsync(user.Id, login));
            UnitTestHelper.IsSuccess(await manager.AddPasswordAsync(user.Id, "password"));
            var logins = await manager.GetLoginsAsync(user.Id);
            Assert.NotNull(logins);
            Assert.Equal(1, logins.Count());
            Assert.Equal(user, await manager.FindAsync(login));
            Assert.Equal(user, await manager.FindAsync(user.UserName, "password"));
        }

        [Fact]
        public void CreateUserLoginAndAddPasswordSyncTest()
        {
            var manager = CreateManager();
            var login = new UserLoginInfo("Provider", "key");
            var user = new InMemoryUser("CreateUserLoginAddPasswordTest");
            UnitTestHelper.IsSuccess(manager.Create(user));
            UnitTestHelper.IsSuccess(manager.AddLogin(user.Id, login));
            UnitTestHelper.IsSuccess(manager.AddPassword(user.Id, "password"));
            var logins = manager.GetLogins(user.Id);
            Assert.NotNull(logins);
            Assert.Equal(1, logins.Count());
            Assert.Equal(user, manager.Find(login));
            Assert.Equal(user, manager.Find(user.UserName, "password"));
        }

        [Fact]
        public async Task CreateUserAddRemoveLoginTest()
        {
            var manager = CreateManager();
            var user = new InMemoryUser("CreateUserAddRemoveLoginTest");
            var login = new UserLoginInfo("Provider", "key");
            const string password = "password";
            var result = await manager.CreateAsync(user, password);
            Assert.NotNull(user);
            UnitTestHelper.IsSuccess(result);
            UnitTestHelper.IsSuccess(await manager.AddLoginAsync(user.Id, login));
            Assert.Equal(user, await manager.FindAsync(login));
            var logins = await manager.GetLoginsAsync(user.Id);
            Assert.NotNull(logins);
            Assert.Equal(1, logins.Count());
            Assert.Equal(login.LoginProvider, logins.Last().LoginProvider);
            Assert.Equal(login.ProviderKey, logins.Last().ProviderKey);
            var stamp = user.SecurityStamp;
            UnitTestHelper.IsSuccess(await manager.RemoveLoginAsync(user.Id, login));
            Assert.Null(await manager.FindAsync(login));
            logins = await manager.GetLoginsAsync(user.Id);
            Assert.NotNull(logins);
            Assert.Equal(0, logins.Count());
            Assert.NotEqual(stamp, user.SecurityStamp);
        }

        [Fact]
        public async Task RemovePasswordTest()
        {
            var manager = CreateManager();
            var user = new InMemoryUser("RemovePasswordTest");
            const string password = "password";
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user, password));
            var stamp = user.SecurityStamp;
            UnitTestHelper.IsSuccess(await manager.RemovePasswordAsync(user.Id));
            var u = await manager.FindByNameAsync(user.UserName);
            Assert.NotNull(u);
            Assert.Null(u.PasswordHash);
            Assert.NotEqual(stamp, user.SecurityStamp);
        }

        [Fact]
        public void RemovePasswordSyncTest()
        {
            var manager = CreateManager();
            var user = new InMemoryUser("RemovePasswordTest");
            const string password = "password";
            UnitTestHelper.IsSuccess(manager.Create(user, password));
            var stamp = user.SecurityStamp;
            UnitTestHelper.IsSuccess(manager.RemovePassword(user.Id));
            var u = manager.FindByName(user.UserName);
            Assert.NotNull(u);
            Assert.Null(u.PasswordHash);
            Assert.NotEqual(stamp, user.SecurityStamp);
        }

        [Fact]
        public async Task ChangePasswordTest()
        {
            var manager = CreateManager();
            var user = new InMemoryUser("ChangePasswordTest");
            const string password = "password";
            const string newPassword = "newpassword";
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user, password));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            UnitTestHelper.IsSuccess(await manager.ChangePasswordAsync(user.Id, password, newPassword));
            Assert.Null(await manager.FindAsync(user.UserName, password));
            Assert.Equal(user, await manager.FindAsync(user.UserName, newPassword));
            Assert.NotEqual(stamp, user.SecurityStamp);
        }

        [Fact]
        public void ChangePasswordSyncTest()
        {
            var manager = CreateManager();
            var user = new InMemoryUser("ChangePasswordTest");
            const string password = "password";
            const string newPassword = "newpassword";
            UnitTestHelper.IsSuccess(manager.Create(user, password));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            UnitTestHelper.IsSuccess(manager.ChangePassword(user.Id, password, newPassword));
            Assert.Null(manager.Find(user.UserName, password));
            Assert.Equal(user, manager.Find(user.UserName, newPassword));
            Assert.NotEqual(stamp, user.SecurityStamp);
        }

        [Fact]
        public async Task AddRemoveUserClaimTest()
        {
            var manager = CreateManager();
            var user = new InMemoryUser("ClaimsAddRemove");
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            Claim[] claims = {new Claim("c", "v"), new Claim("c2", "v2"), new Claim("c2", "v3")};
            foreach (Claim c in claims)
            {
                UnitTestHelper.IsSuccess(await manager.AddClaimAsync(user.Id, c));
            }
            var userClaims = await manager.GetClaimsAsync(user.Id);
            Assert.Equal(3, userClaims.Count);
            UnitTestHelper.IsSuccess(await manager.RemoveClaimAsync(user.Id, claims[0]));
            userClaims = await manager.GetClaimsAsync(user.Id);
            Assert.Equal(2, userClaims.Count);
            UnitTestHelper.IsSuccess(await manager.RemoveClaimAsync(user.Id, claims[1]));
            userClaims = await manager.GetClaimsAsync(user.Id);
            Assert.Equal(1, userClaims.Count);
            UnitTestHelper.IsSuccess(await manager.RemoveClaimAsync(user.Id, claims[2]));
            userClaims = await manager.GetClaimsAsync(user.Id);
            Assert.Equal(0, userClaims.Count);
        }

        [Fact]
        public void AddRemoveUserClaimSyncTest()
        {
            var manager = CreateManager();
            var user = new InMemoryUser("ClaimsAddRemove");
            UnitTestHelper.IsSuccess(manager.Create(user));
            Claim[] claims = {new Claim("c", "v"), new Claim("c2", "v2"), new Claim("c2", "v3")};
            foreach (Claim c in claims)
            {
                UnitTestHelper.IsSuccess(manager.AddClaim(user.Id, c));
            }
            var userClaims = manager.GetClaims(user.Id);
            Assert.Equal(3, userClaims.Count);
            UnitTestHelper.IsSuccess(manager.RemoveClaim(user.Id, claims[0]));
            userClaims = manager.GetClaims(user.Id);
            Assert.Equal(2, userClaims.Count);
            UnitTestHelper.IsSuccess(manager.RemoveClaim(user.Id, claims[1]));
            userClaims = manager.GetClaims(user.Id);
            Assert.Equal(1, userClaims.Count);
            UnitTestHelper.IsSuccess(manager.RemoveClaim(user.Id, claims[2]));
            userClaims = manager.GetClaims(user.Id);
            Assert.Equal(0, userClaims.Count);
        }

        [Fact]
        public async Task ChangePasswordFallsIfPasswordTooShortTest()
        {
            var manager = CreateManager();
            var user = new InMemoryUser("user");
            const string password = "password";
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user, password));
            var result = await manager.ChangePasswordAsync(user.Id, password, "n");
            UnitTestHelper.IsFailure(result, "Passwords must be at least 6 characters.");
        }

        [Fact]
        public async Task ChangePasswordFallsIfPasswordWrongTest()
        {
            var manager = CreateManager();
            var user = new InMemoryUser("user");
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user, "password"));
            var result = await manager.ChangePasswordAsync(user.Id, "bogus", "newpassword");
            UnitTestHelper.IsFailure(result, "Incorrect password.");
        }

        [Fact]
        public void ChangePasswordFallsIfPasswordWrongSyncTest()
        {
            var manager = CreateManager();
            var user = new InMemoryUser("user");
            UnitTestHelper.IsSuccess(manager.Create(user, "password"));
            var result = manager.ChangePassword(user.Id, "bogus", "newpassword");
            UnitTestHelper.IsFailure(result, "Incorrect password.");
        }

        [Fact]
        public async Task CanRelaxUserNameAndPasswordValidationTest()
        {
            var manager = CreateManager();
            manager.UserValidator = new UserValidator<InMemoryUser>(manager) {AllowOnlyAlphanumericUserNames = false};
            manager.PasswordValidator = new MinimumLengthValidator(1);
            UnitTestHelper.IsSuccess(await manager.CreateAsync(new InMemoryUser("Some spaces"), "pwd"));
        }

        [Fact]
        public async Task AddDupeUserFailsTest()
        {
            var manager = CreateManager();
            var user = new InMemoryUser("dupe");
            var user2 = new InMemoryUser("dupe");
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            UnitTestHelper.IsFailure(await manager.CreateAsync(user2), "Name dupe is already taken.");
        }

        [Fact]
        public async Task UpdateSecurityStampTest()
        {
            var manager = CreateManager();
            var user = new InMemoryUser("stampMe");
            Assert.Null(user.SecurityStamp);
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            UnitTestHelper.IsSuccess(await manager.UpdateSecurityStampAsync(user.Id));
            Assert.NotEqual(stamp, user.SecurityStamp);
        }

        [Fact]
        public void UpdateSecurityStampSyncTest()
        {
            var manager = CreateManager();
            var user = new InMemoryUser("stampMe");
            Assert.Null(user.SecurityStamp);
            UnitTestHelper.IsSuccess(manager.Create(user));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            UnitTestHelper.IsSuccess(manager.UpdateSecurityStamp(user.Id));
            Assert.NotEqual(stamp, user.SecurityStamp);
        }

        [Fact]
        public async Task AddDupeLoginFailsTest()
        {
            var manager = CreateManager();
            var user = new InMemoryUser("DupeLogin");
            var login = new UserLoginInfo("provder", "key");
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            UnitTestHelper.IsSuccess(await manager.AddLoginAsync(user.Id, login));
            var result = await manager.AddLoginAsync(user.Id, login);
            UnitTestHelper.IsFailure(result, "A user with that external login already exists.");
        }

        // Lockout tests

        [Fact]
        public async Task SingleFailureLockout()
        {
            var mgr = CreateManager();
            mgr.DefaultAccountLockoutTimeSpan = TimeSpan.FromHours(1);
            mgr.UserLockoutEnabledByDefault = true;
            var user = new InMemoryUser("fastLockout");
            UnitTestHelper.IsSuccess(await mgr.CreateAsync(user));
            Assert.True(await mgr.GetLockoutEnabledAsync(user.Id));
            Assert.True(user.LockoutEnabled);
            Assert.False(await mgr.IsLockedOutAsync(user.Id));
            UnitTestHelper.IsSuccess(await mgr.AccessFailedAsync(user.Id));
            Assert.True(await mgr.IsLockedOutAsync(user.Id));
            Assert.True(await mgr.GetLockoutEndDateAsync(user.Id) > DateTimeOffset.UtcNow.AddMinutes(55));
            Assert.Equal(0, await mgr.GetAccessFailedCountAsync(user.Id));
        }

        [Fact]
        public async Task TwoFailureLockout()
        {
            var mgr = CreateManager();
            mgr.DefaultAccountLockoutTimeSpan = TimeSpan.FromHours(1);
            mgr.UserLockoutEnabledByDefault = true;
            mgr.MaxFailedAccessAttemptsBeforeLockout = 2;
            var user = new InMemoryUser("twoFailureLockout");
            UnitTestHelper.IsSuccess(await mgr.CreateAsync(user));
            Assert.True(await mgr.GetLockoutEnabledAsync(user.Id));
            Assert.True(user.LockoutEnabled);
            Assert.False(await mgr.IsLockedOutAsync(user.Id));
            UnitTestHelper.IsSuccess(await mgr.AccessFailedAsync(user.Id));
            Assert.False(await mgr.IsLockedOutAsync(user.Id));
            Assert.False(await mgr.GetLockoutEndDateAsync(user.Id) > DateTimeOffset.UtcNow.AddMinutes(55));
            Assert.Equal(1, await mgr.GetAccessFailedCountAsync(user.Id));
            UnitTestHelper.IsSuccess(await mgr.AccessFailedAsync(user.Id));
            Assert.True(await mgr.IsLockedOutAsync(user.Id));
            Assert.True(await mgr.GetLockoutEndDateAsync(user.Id) > DateTimeOffset.UtcNow.AddMinutes(55));
            Assert.Equal(0, await mgr.GetAccessFailedCountAsync(user.Id));
        }

        [Fact]
        public async Task ResetLockoutTest()
        {
            var mgr = CreateManager();
            mgr.DefaultAccountLockoutTimeSpan = TimeSpan.FromHours(1);
            mgr.UserLockoutEnabledByDefault = true;
            mgr.MaxFailedAccessAttemptsBeforeLockout = 2;
            var user = new InMemoryUser("resetLockout");
            UnitTestHelper.IsSuccess(await mgr.CreateAsync(user));
            Assert.True(await mgr.GetLockoutEnabledAsync(user.Id));
            Assert.True(user.LockoutEnabled);
            Assert.False(await mgr.IsLockedOutAsync(user.Id));
            UnitTestHelper.IsSuccess(await mgr.AccessFailedAsync(user.Id));
            Assert.False(await mgr.IsLockedOutAsync(user.Id));
            Assert.False(await mgr.GetLockoutEndDateAsync(user.Id) > DateTimeOffset.UtcNow.AddMinutes(55));
            Assert.Equal(1, await mgr.GetAccessFailedCountAsync(user.Id));
            UnitTestHelper.IsSuccess(await mgr.ResetAccessFailedCountAsync(user.Id));
            Assert.Equal(0, await mgr.GetAccessFailedCountAsync(user.Id));
            Assert.False(await mgr.IsLockedOutAsync(user.Id));
            Assert.False(await mgr.GetLockoutEndDateAsync(user.Id) > DateTimeOffset.UtcNow.AddMinutes(55));
            UnitTestHelper.IsSuccess(await mgr.AccessFailedAsync(user.Id));
            Assert.False(await mgr.IsLockedOutAsync(user.Id));
            Assert.False(await mgr.GetLockoutEndDateAsync(user.Id) > DateTimeOffset.UtcNow.AddMinutes(55));
            Assert.Equal(1, await mgr.GetAccessFailedCountAsync(user.Id));
        }

        [Fact]
        public void ResetLockoutSync()
        {
            var mgr = CreateManager();
            mgr.DefaultAccountLockoutTimeSpan = TimeSpan.FromHours(1);
            mgr.UserLockoutEnabledByDefault = true;
            mgr.MaxFailedAccessAttemptsBeforeLockout = 2;
            var user = new InMemoryUser("resetLockout");
            UnitTestHelper.IsSuccess(mgr.Create(user));
            Assert.True(mgr.GetLockoutEnabled(user.Id));
            Assert.True(user.LockoutEnabled);
            Assert.False(mgr.IsLockedOut(user.Id));
            UnitTestHelper.IsSuccess(mgr.AccessFailed(user.Id));
            Assert.False(mgr.IsLockedOut(user.Id));
            Assert.False(mgr.GetLockoutEndDate(user.Id) > DateTimeOffset.UtcNow.AddMinutes(55));
            Assert.Equal(1, mgr.GetAccessFailedCount(user.Id));
            UnitTestHelper.IsSuccess(mgr.ResetAccessFailedCount(user.Id));
            Assert.Equal(0, mgr.GetAccessFailedCount(user.Id));
            Assert.False(mgr.IsLockedOut(user.Id));
            Assert.False(mgr.GetLockoutEndDate(user.Id) > DateTimeOffset.UtcNow.AddMinutes(55));
            UnitTestHelper.IsSuccess(mgr.AccessFailed(user.Id));
            Assert.False(mgr.IsLockedOut(user.Id));
            Assert.False(mgr.GetLockoutEndDate(user.Id) > DateTimeOffset.UtcNow.AddMinutes(55));
            Assert.Equal(1, mgr.GetAccessFailedCount(user.Id));
        }

        [Fact]
        public async Task EnableLockoutManually()
        {
            var mgr = CreateManager();
            mgr.DefaultAccountLockoutTimeSpan = TimeSpan.FromHours(1);
            mgr.MaxFailedAccessAttemptsBeforeLockout = 2;
            var user = new InMemoryUser("manualLockout");
            UnitTestHelper.IsSuccess(await mgr.CreateAsync(user));
            Assert.False(await mgr.GetLockoutEnabledAsync(user.Id));
            Assert.False(user.LockoutEnabled);
            UnitTestHelper.IsSuccess(await mgr.SetLockoutEnabledAsync(user.Id, true));
            Assert.True(await mgr.GetLockoutEnabledAsync(user.Id));
            Assert.True(user.LockoutEnabled);
            Assert.False(await mgr.IsLockedOutAsync(user.Id));
            UnitTestHelper.IsSuccess(await mgr.AccessFailedAsync(user.Id));
            Assert.False(await mgr.IsLockedOutAsync(user.Id));
            Assert.False(await mgr.GetLockoutEndDateAsync(user.Id) > DateTimeOffset.UtcNow.AddMinutes(55));
            Assert.Equal(1, await mgr.GetAccessFailedCountAsync(user.Id));
            UnitTestHelper.IsSuccess(await mgr.AccessFailedAsync(user.Id));
            Assert.True(await mgr.IsLockedOutAsync(user.Id));
            Assert.True(await mgr.GetLockoutEndDateAsync(user.Id) > DateTimeOffset.UtcNow.AddMinutes(55));
            Assert.Equal(0, await mgr.GetAccessFailedCountAsync(user.Id));
        }

        [Fact]
        public void EnableLockoutManuallySync()
        {
            var mgr = CreateManager();
            mgr.DefaultAccountLockoutTimeSpan = TimeSpan.FromHours(1);
            mgr.MaxFailedAccessAttemptsBeforeLockout = 2;
            var user = new InMemoryUser("manualLockout");
            UnitTestHelper.IsSuccess(mgr.Create(user));
            Assert.False(mgr.GetLockoutEnabled(user.Id));
            Assert.False(user.LockoutEnabled);
            UnitTestHelper.IsSuccess(mgr.SetLockoutEnabled(user.Id, true));
            Assert.True(mgr.GetLockoutEnabled(user.Id));
            Assert.True(user.LockoutEnabled);
            Assert.False(mgr.IsLockedOut(user.Id));
            UnitTestHelper.IsSuccess(mgr.AccessFailed(user.Id));
            Assert.False(mgr.IsLockedOut(user.Id));
            Assert.False(mgr.GetLockoutEndDate(user.Id) > DateTimeOffset.UtcNow.AddMinutes(55));
            Assert.Equal(1, mgr.GetAccessFailedCount(user.Id));
            UnitTestHelper.IsSuccess(mgr.AccessFailed(user.Id));
            Assert.True(mgr.IsLockedOut(user.Id));
            Assert.True(mgr.GetLockoutEndDate(user.Id) > DateTimeOffset.UtcNow.AddMinutes(55));
            Assert.Equal(0, mgr.GetAccessFailedCount(user.Id));
        }

        [Fact]
        public async Task UserNotLockedOutWithNullDateTimeAndIsSetToNullDate()
        {
            var mgr = CreateManager();
            mgr.UserLockoutEnabledByDefault = true;
            var user = new InMemoryUser("LockoutTest");
            UnitTestHelper.IsSuccess(mgr.Create(user));
            Assert.True(mgr.GetLockoutEnabled(user.Id));
            Assert.True(user.LockoutEnabled);
            UnitTestHelper.IsSuccess(await mgr.SetLockoutEndDateAsync(user.Id, new DateTimeOffset()));
            Assert.False(await mgr.IsLockedOutAsync(user.Id));
            Assert.Equal(new DateTimeOffset(), await mgr.GetLockoutEndDateAsync(user.Id));
            Assert.Equal(new DateTimeOffset(), user.LockoutEnd);
        }

        [Fact]
        public async Task LockoutFailsIfNotEnabled()
        {
            var mgr = CreateManager();
            var user = new InMemoryUser("LockoutNotEnabledTest");
            UnitTestHelper.IsSuccess(mgr.Create(user));
            Assert.False(mgr.GetLockoutEnabled(user.Id));
            Assert.False(user.LockoutEnabled);
            UnitTestHelper.IsFailure(await mgr.SetLockoutEndDateAsync(user.Id, new DateTimeOffset()), "Lockout is not enabled for this user.");
            Assert.False(await mgr.IsLockedOutAsync(user.Id));
        }

        [Fact]
        public async Task LockoutEndToUtcNowMinus1SecInUserShouldNotBeLockedOut()
        {
            var mgr = CreateManager();
            mgr.UserLockoutEnabledByDefault = true;
            var user = new InMemoryUser("LockoutUtcNowTest") { LockoutEnd = DateTimeOffset.UtcNow.AddSeconds(-1) };
            UnitTestHelper.IsSuccess(mgr.Create(user));
            Assert.True(mgr.GetLockoutEnabled(user.Id));
            Assert.True(user.LockoutEnabled);
            Assert.False(await mgr.IsLockedOutAsync(user.Id));
        }

        [Fact]
        public async Task LockoutEndToUtcNowWithManagerShouldNotBeLockedOut()
        {
            var mgr = CreateManager();
            mgr.UserLockoutEnabledByDefault = true;
            var user = new InMemoryUser("LockoutUtcNowTest");
            UnitTestHelper.IsSuccess(mgr.Create(user));
            Assert.True(mgr.GetLockoutEnabled(user.Id));
            Assert.True(user.LockoutEnabled);
            UnitTestHelper.IsSuccess(await mgr.SetLockoutEndDateAsync(user.Id, DateTimeOffset.UtcNow.AddSeconds(-.5)));
            Assert.False(await mgr.IsLockedOutAsync(user.Id));
        }

        [Fact]
        public async Task LockoutEndToUtcNowPlus5ShouldBeLockedOut()
        {
            var mgr = CreateManager();
            mgr.UserLockoutEnabledByDefault = true;
            var user = new InMemoryUser("LockoutUtcNowTest") { LockoutEnd = DateTimeOffset.UtcNow.AddMinutes(5) };
            UnitTestHelper.IsSuccess(mgr.Create(user));
            Assert.True(mgr.GetLockoutEnabled(user.Id));
            Assert.True(user.LockoutEnabled);
            Assert.True(await mgr.IsLockedOutAsync(user.Id));
        }

        [Fact]
        public void UserLockedOutWithDateTimeNowPlus30Sync()
        {
            var mgr = CreateManager();
            mgr.UserLockoutEnabledByDefault = true;
            var user = new InMemoryUser("LockoutTest");
            UnitTestHelper.IsSuccess(mgr.Create(user));
            Assert.True(mgr.GetLockoutEnabled(user.Id));
            Assert.True(user.LockoutEnabled);
            var lockoutEnd = new DateTimeOffset(DateTime.Now.AddMinutes(30));
            UnitTestHelper.IsSuccess(mgr.SetLockoutEndDate(user.Id, lockoutEnd));
            Assert.True(mgr.IsLockedOut(user.Id));
            var end = mgr.GetLockoutEndDate(user.Id);
            Assert.Equal(lockoutEnd, end);
        }

        [Fact]
        public async Task UserLockedOutWithDateTimeLocalKindNowPlus30()
        {
            var mgr = CreateManager();
            mgr.UserLockoutEnabledByDefault = true;
            var user = new InMemoryUser("LockoutTest");
            UnitTestHelper.IsSuccess(mgr.Create(user));
            Assert.True(mgr.GetLockoutEnabled(user.Id));
            Assert.True(user.LockoutEnabled);
            var lockoutEnd = new DateTimeOffset(DateTime.Now.AddMinutes(30).ToLocalTime());
            UnitTestHelper.IsSuccess(await mgr.SetLockoutEndDateAsync(user.Id, lockoutEnd));
            Assert.True(await mgr.IsLockedOutAsync(user.Id));
            var end = await mgr.GetLockoutEndDateAsync(user.Id);
            Assert.Equal(lockoutEnd, end);
        }
 

        // Role Tests
        [Fact]
        public async Task CreateRoleTest()
        {
            var manager = CreateRoleManager();
            var role = new InMemoryRole("create");
            Assert.False(await manager.RoleExistsAsync(role.Name));
            UnitTestHelper.IsSuccess(await manager.CreateAsync(role));
            Assert.True(await manager.RoleExistsAsync(role.Name));
        }

        [Fact]
        public async Task BadValidatorBlocksCreateTest()
        {
            var manager = CreateRoleManager();
            manager.RoleValidator = new AlwaysBadValidator<InMemoryRole>();
            UnitTestHelper.IsFailure(await manager.CreateAsync(new InMemoryRole("blocked")),
                AlwaysBadValidator<InMemoryRole>.ErrorMessage);
        }

        [Fact]
        public async Task BadValidatorBlocksAllUpdatesTest()
        {
            var manager = CreateRoleManager();
            var role = new InMemoryRole("poorguy");
            UnitTestHelper.IsSuccess(await manager.CreateAsync(role));
            var error = AlwaysBadValidator<InMemoryRole>.ErrorMessage;
            manager.RoleValidator = new AlwaysBadValidator<InMemoryRole>();
            UnitTestHelper.IsFailure(await manager.UpdateAsync(role), error);
        }

        [Fact]
        public async Task DeleteRoleTest()
        {
            var manager = CreateRoleManager();
            var role = new InMemoryRole("delete");
            Assert.False(await manager.RoleExistsAsync(role.Name));
            UnitTestHelper.IsSuccess(await manager.CreateAsync(role));
            UnitTestHelper.IsSuccess(await manager.DeleteAsync(role));
            Assert.False(await manager.RoleExistsAsync(role.Name));
        }

        [Fact]
        public async Task RoleFindByIdTest()
        {
            var manager = CreateRoleManager();
            var role = new InMemoryRole("FindById");
            Assert.Null(await manager.FindByIdAsync(role.Id));
            UnitTestHelper.IsSuccess(await manager.CreateAsync(role));
            Assert.Equal(role, await manager.FindByIdAsync(role.Id));
        }

        [Fact]
        public async Task RoleFindByNameTest()
        {
            var manager = CreateRoleManager();
            var role = new InMemoryRole("FindByName");
            Assert.Null(await manager.FindByNameAsync(role.Name));
            Assert.False(await manager.RoleExistsAsync(role.Name));
            UnitTestHelper.IsSuccess(await manager.CreateAsync(role));
            Assert.Equal(role, await manager.FindByNameAsync(role.Name));
        }

        [Fact]
        public async Task UpdateRoleNameTest()
        {
            var manager = CreateRoleManager();
            var role = new InMemoryRole("update");
            Assert.False(await manager.RoleExistsAsync(role.Name));
            UnitTestHelper.IsSuccess(await manager.CreateAsync(role));
            Assert.True(await manager.RoleExistsAsync(role.Name));
            role.Name = "Changed";
            UnitTestHelper.IsSuccess(await manager.UpdateAsync(role));
            Assert.False(await manager.RoleExistsAsync("update"));
            Assert.Equal(role, await manager.FindByNameAsync(role.Name));
        }

        [Fact]
        public async Task QuerableRolesTest()
        {
            var manager = CreateRoleManager();
            InMemoryRole[] roles =
            {
                new InMemoryRole("r1"), new InMemoryRole("r2"), new InMemoryRole("r3"),
                new InMemoryRole("r4")
            };
            foreach (var r in roles)
            {
                UnitTestHelper.IsSuccess(await manager.CreateAsync(r));
            }
            Assert.Equal(roles.Length, manager.Roles.Count());
            var r1 = manager.Roles.FirstOrDefault(r => r.Name == "r1");
            Assert.Equal(roles[0], r1);
        }

        [Fact]
        public async Task DeleteRoleNonEmptySucceedsTest()
        {
            // Need fail if not empty?
            var userMgr = CreateManager();
            var roleMgr = CreateRoleManager();
            var role = new InMemoryRole("deleteNonEmpty");
            Assert.False(await roleMgr.RoleExistsAsync(role.Name));
            UnitTestHelper.IsSuccess(await roleMgr.CreateAsync(role));
            var user = new InMemoryUser("t");
            UnitTestHelper.IsSuccess(await userMgr.CreateAsync(user));
            UnitTestHelper.IsSuccess(await userMgr.AddToRoleAsync(user.Id, role.Name));
            UnitTestHelper.IsSuccess(await roleMgr.DeleteAsync(role));
            Assert.Null(await roleMgr.FindByNameAsync(role.Name));
            Assert.False(await roleMgr.RoleExistsAsync(role.Name));
            // REVIEW: We should throw if deleteing a non empty role?
            var roles = await userMgr.GetRolesAsync(user.Id);

            // In memory this doesn't work since there's no concept of cascading deletes
            //Assert.Equal(0, roles.Count());
        }

        //[Fact]
        //public async Task DeleteUserRemovesFromRoleTest()
        //{
        //    // Need fail if not empty?
        //    var userMgr = CreateManager();
        //    var roleMgr = CreateRoleManager();
        //    var role = new InMemoryRole("deleteNonEmpty");
        //    Assert.False(await roleMgr.RoleExistsAsync(role.Name));
        //    UnitTestHelper.IsSuccess(await roleMgr.CreateAsync(role));
        //    var user = new InMemoryUser("t");
        //    UnitTestHelper.IsSuccess(await userMgr.CreateAsync(user));
        //    UnitTestHelper.IsSuccess(await userMgr.AddToRoleAsync(user.Id, role.Name));
        //    UnitTestHelper.IsSuccess(await userMgr.DeleteAsync(user));
        //    role = roleMgr.FindById(role.Id);
        //}

        [Fact]
        public async Task DeleteRoleUnknownFailsTest()
        {
            var manager = CreateRoleManager();
            var role = new InMemoryRole("bogus");
            Assert.False(await manager.RoleExistsAsync(role.Name));
            Assert.Throws<InvalidOperationException>(() => AsyncHelper.RunSync(() => manager.DeleteAsync(role)));
        }

        [Fact]
        public async Task CreateRoleFailsIfExistsTest()
        {
            var manager = CreateRoleManager();
            var role = new InMemoryRole("dupeRole");
            Assert.False(await manager.RoleExistsAsync(role.Name));
            UnitTestHelper.IsSuccess(await manager.CreateAsync(role));
            Assert.True(await manager.RoleExistsAsync(role.Name));
            var role2 = new InMemoryRole("dupeRole");
            UnitTestHelper.IsFailure(await manager.CreateAsync(role2));
        }

        [Fact]
        public async Task AddUserToRoleTest()
        {
            var manager = CreateManager();
            var roleManager = CreateRoleManager();
            var role = new InMemoryRole("addUserTest");
            UnitTestHelper.IsSuccess(await roleManager.CreateAsync(role));
            InMemoryUser[] users =
            {
                new InMemoryUser("1"), new InMemoryUser("2"), new InMemoryUser("3"),
                new InMemoryUser("4")
            };
            foreach (InMemoryUser u in users)
            {
                UnitTestHelper.IsSuccess(await manager.CreateAsync(u));
                UnitTestHelper.IsSuccess(await manager.AddToRoleAsync(u.Id, role.Name));
                Assert.True(await manager.IsInRoleAsync(u.Id, role.Name));
            }
        }

        [Fact]
        public async Task GetRolesForUserTest()
        {
            var userManager = CreateManager();
            var roleManager = CreateRoleManager();
            InMemoryUser[] users =
            {
                new InMemoryUser("u1"), new InMemoryUser("u2"), new InMemoryUser("u3"),
                new InMemoryUser("u4")
            };
            InMemoryRole[] roles =
            {
                new InMemoryRole("r1"), new InMemoryRole("r2"), new InMemoryRole("r3"),
                new InMemoryRole("r4")
            };
            foreach (var u in users)
            {
                UnitTestHelper.IsSuccess(await userManager.CreateAsync(u));
            }
            foreach (var r in roles)
            {
                UnitTestHelper.IsSuccess(await roleManager.CreateAsync(r));
                foreach (var u in users)
                {
                    UnitTestHelper.IsSuccess(await userManager.AddToRoleAsync(u.Id, r.Name));
                    Assert.True(await userManager.IsInRoleAsync(u.Id, r.Name));
                }
            }

            foreach (var u in users)
            {
                var rs = await userManager.GetRolesAsync(u.Id);
                Assert.Equal(roles.Length, rs.Count);
                foreach (var r in roles)
                {
                    Assert.True(rs.Any(role => role == r.Name));
                }
            }
        }


        [Fact]
        public async Task RemoveUserFromRoleWithMultipleRoles()
        {
            var userManager = CreateManager();
            var roleManager = CreateRoleManager();
            var user = new InMemoryUser("MultiRoleUser");
            UnitTestHelper.IsSuccess(await userManager.CreateAsync(user));
            InMemoryRole[] roles =
            {
                new InMemoryRole("r1"), new InMemoryRole("r2"), new InMemoryRole("r3"),
                new InMemoryRole("r4")
            };
            foreach (var r in roles)
            {
                UnitTestHelper.IsSuccess(await roleManager.CreateAsync(r));
                UnitTestHelper.IsSuccess(await userManager.AddToRoleAsync(user.Id, r.Name));
                Assert.True(await userManager.IsInRoleAsync(user.Id, r.Name));
            }
            UnitTestHelper.IsSuccess(await userManager.RemoveFromRoleAsync(user.Id, roles[2].Name));
            Assert.False(await userManager.IsInRoleAsync(user.Id, roles[2].Name));
        }

        [Fact]
        public async Task RemoveUserFromRoleTest()
        {
            var userManager = CreateManager();
            var roleManager = CreateRoleManager();
            InMemoryUser[] users =
            {
                new InMemoryUser("1"), new InMemoryUser("2"), new InMemoryUser("3"),
                new InMemoryUser("4")
            };
            foreach (var u in users)
            {
                UnitTestHelper.IsSuccess(await userManager.CreateAsync(u, "password"));
            }
            var r = new InMemoryRole("r1");
            UnitTestHelper.IsSuccess(await roleManager.CreateAsync(r));
            foreach (var u in users)
            {
                UnitTestHelper.IsSuccess(await userManager.AddToRoleAsync(u.Id, r.Name));
                Assert.True(await userManager.IsInRoleAsync(u.Id, r.Name));
            }
            foreach (var u in users)
            {
                UnitTestHelper.IsSuccess(await userManager.RemoveFromRoleAsync(u.Id, r.Name));
                Assert.False(await userManager.IsInRoleAsync(u.Id, r.Name));
            }
        }

        [Fact]
        public async Task RemoveUserNotInRoleFailsTest()
        {
            var userMgr = CreateManager();
            var roleMgr = CreateRoleManager();
            var role = new InMemoryRole("addUserDupeTest");
            var user = new InMemoryUser("user1");
            UnitTestHelper.IsSuccess(await userMgr.CreateAsync(user));
            UnitTestHelper.IsSuccess(await roleMgr.CreateAsync(role));
            var result = await userMgr.RemoveFromRoleAsync(user.Id, role.Name);
            UnitTestHelper.IsFailure(result, "User is not in role.");
        }

        [Fact]
        public async Task AddUserToRoleFailsIfAlreadyInRoleTest()
        {
            var userMgr = CreateManager();
            var roleMgr = CreateRoleManager();
            var role = new InMemoryRole("addUserDupeTest");
            var user = new InMemoryUser("user1");
            UnitTestHelper.IsSuccess(await userMgr.CreateAsync(user));
            UnitTestHelper.IsSuccess(await roleMgr.CreateAsync(role));
            UnitTestHelper.IsSuccess(await userMgr.AddToRoleAsync(user.Id, role.Name));
            Assert.True(await userMgr.IsInRoleAsync(user.Id, role.Name));
            UnitTestHelper.IsFailure(await userMgr.AddToRoleAsync(user.Id, role.Name), "User already in role.");
        }

        [Fact]
        public async Task FindRoleByNameWithManagerTest()
        {
            var roleMgr = CreateRoleManager();
            var role = new InMemoryRole("findRoleByNameTest");
            UnitTestHelper.IsSuccess(await roleMgr.CreateAsync(role));
            Assert.Equal(role.Id, (await roleMgr.FindByNameAsync(role.Name)).Id);
        }

        [Fact]
        public async Task FindRoleWithManagerTest()
        {
            var roleMgr = CreateRoleManager();
            var role = new InMemoryRole("findRoleTest");
            UnitTestHelper.IsSuccess(await roleMgr.CreateAsync(role));
            Assert.Equal(role.Name, (await roleMgr.FindByIdAsync(role.Id)).Name);
        }


        private static UserManager<InMemoryUser> CreateManager()
        {
            return new UserManager<InMemoryUser>(new InMemoryUserStore());
        }

        private static RoleManager<InMemoryRole> CreateRoleManager()
        {
            return new RoleManager<InMemoryRole>(new InMemoryRoleStore());
        }
    }
}