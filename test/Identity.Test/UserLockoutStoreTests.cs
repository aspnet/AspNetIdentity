// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Xunit;

namespace Identity.Test
{
    public class UserLockoutStoreTests
    {
        [Fact]
        public async Task VerifyDefaultLockoutIsOff()
        {
            var mgr = TestUtil.CreateManager();
            var user = new IdentityUser("lockoutDefaults");
            Assert.False(mgr.UserLockoutEnabledByDefault);
            UnitTestHelper.IsSuccess(await mgr.CreateAsync(user));
            Assert.False(await mgr.GetLockoutEnabledAsync(user.Id));
            Assert.False(user.LockoutEnabled);
        }

        [Fact]
        public async Task SingleFailureLockout()
        {
            var mgr = TestUtil.CreateManager();
            mgr.DefaultAccountLockoutTimeSpan = TimeSpan.FromHours(1);
            mgr.UserLockoutEnabledByDefault = true;
            var user = new IdentityUser("fastLockout");
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
            var mgr = TestUtil.CreateManager();
            mgr.DefaultAccountLockoutTimeSpan = TimeSpan.FromHours(1);
            mgr.UserLockoutEnabledByDefault = true;
            mgr.MaxFailedAccessAttemptsBeforeLockout = 2;
            var user = new IdentityUser("twoFailureLockout");
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
            var mgr = TestUtil.CreateManager();
            mgr.DefaultAccountLockoutTimeSpan = TimeSpan.FromHours(1);
            mgr.UserLockoutEnabledByDefault = true;
            mgr.MaxFailedAccessAttemptsBeforeLockout = 2;
            var user = new IdentityUser("resetLockout");
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
            var mgr = TestUtil.CreateManager();
            mgr.DefaultAccountLockoutTimeSpan = TimeSpan.FromHours(1);
            mgr.UserLockoutEnabledByDefault = true;
            mgr.MaxFailedAccessAttemptsBeforeLockout = 2;
            var user = new IdentityUser("resetLockout");
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
            var mgr = TestUtil.CreateManager();
            mgr.DefaultAccountLockoutTimeSpan = TimeSpan.FromHours(1);
            mgr.MaxFailedAccessAttemptsBeforeLockout = 2;
            var user = new IdentityUser("manualLockout");
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
            var mgr = TestUtil.CreateManager();
            mgr.DefaultAccountLockoutTimeSpan = TimeSpan.FromHours(1);
            mgr.MaxFailedAccessAttemptsBeforeLockout = 2;
            var user = new IdentityUser("manualLockout");
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
            var mgr = TestUtil.CreateManager();
            mgr.UserLockoutEnabledByDefault = true;
            var user = new IdentityUser("LockoutTest");
            UnitTestHelper.IsSuccess(mgr.Create(user));
            Assert.True(mgr.GetLockoutEnabled(user.Id));
            Assert.True(user.LockoutEnabled);
            UnitTestHelper.IsSuccess(await mgr.SetLockoutEndDateAsync(user.Id, new DateTimeOffset()));
            Assert.False(await mgr.IsLockedOutAsync(user.Id));
            Assert.Equal(new DateTimeOffset(), await mgr.GetLockoutEndDateAsync(user.Id));
            Assert.Null(user.LockoutEndDateUtc);
        }

        [Fact]
        public async Task LockoutFailsIfNotEnabled() {
            var mgr = TestUtil.CreateManager();
            var user = new IdentityUser("LockoutNotEnabledTest");
            UnitTestHelper.IsSuccess(mgr.Create(user));
            Assert.False(mgr.GetLockoutEnabled(user.Id));
            Assert.False(user.LockoutEnabled);
            UnitTestHelper.IsFailure(await mgr.SetLockoutEndDateAsync(user.Id, new DateTimeOffset()), "Lockout is not enabled for this user.");
            Assert.False(await mgr.IsLockedOutAsync(user.Id));
        }

        [Fact]
        public async Task LockoutEndToUtcNowInUserShouldNotBeLockedOut()
        {
            var mgr = TestUtil.CreateManager();
            mgr.UserLockoutEnabledByDefault = true;
            var user = new IdentityUser("LockoutUtcNowTest") { LockoutEndDateUtc = DateTime.UtcNow };
            UnitTestHelper.IsSuccess(mgr.Create(user));
            Assert.True(mgr.GetLockoutEnabled(user.Id));
            Assert.True(user.LockoutEnabled);
            Assert.False(await mgr.IsLockedOutAsync(user.Id));
        }

 
        [Fact]
        public async Task LockoutEndToUtcNowWithManagerShouldNotBeLockedOut()
        {
            var mgr = TestUtil.CreateManager();
            mgr.UserLockoutEnabledByDefault = true;
            var user = new IdentityUser("LockoutUtcNowTest");
            UnitTestHelper.IsSuccess(mgr.Create(user));
            Assert.True(mgr.GetLockoutEnabled(user.Id));
            Assert.True(user.LockoutEnabled);
            var now = new DateTime(DateTime.UtcNow.Ticks, DateTimeKind.Utc);
            UnitTestHelper.IsSuccess(await mgr.SetLockoutEndDateAsync(user.Id, new DateTimeOffset(now)));
            Assert.False(await mgr.IsLockedOutAsync(user.Id));
        }

        [Fact]
        public async Task LockoutEndToUtcNowPlus5ShouldBeLockedOut()
        {
            var mgr = TestUtil.CreateManager();
            mgr.UserLockoutEnabledByDefault = true;
            var user = new IdentityUser("LockoutUtcNowTest") { LockoutEndDateUtc = DateTime.UtcNow.AddMinutes(5) };
            UnitTestHelper.IsSuccess(mgr.Create(user));
            Assert.True(mgr.GetLockoutEnabled(user.Id));
            Assert.True(user.LockoutEnabled);
            Assert.True(await mgr.IsLockedOutAsync(user.Id));
        }

        [Fact]
        public async Task LockoutEndToNowPlus5ShouldNotBeLockedOut()
        {
            var mgr = TestUtil.CreateManager();
            mgr.UserLockoutEnabledByDefault = true;
            var user = new IdentityUser("LockoutNowTest") { LockoutEndDateUtc = DateTime.Now.AddMinutes(5) };
            UnitTestHelper.IsSuccess(mgr.Create(user));
            Assert.True(mgr.GetLockoutEnabled(user.Id));
            Assert.True(user.LockoutEnabled);
            // UTC is 8 hours earlier, so no lockout
            Assert.False(await mgr.IsLockedOutAsync(user.Id));
        }

        [Fact]
        public async Task UserLockedOutWithDateTimeNowPlus30()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var mgr = TestUtil.CreateManager(db);
            mgr.UserLockoutEnabledByDefault = true;
            var user = new IdentityUser("LockoutTest");
            UnitTestHelper.IsSuccess(mgr.Create(user));
            Assert.True(mgr.GetLockoutEnabled(user.Id));
            Assert.True(user.LockoutEnabled);
            var lockoutEnd = new DateTimeOffset(DateTime.Now.AddMinutes(30));
            UnitTestHelper.IsSuccess(await mgr.SetLockoutEndDateAsync(user.Id, lockoutEnd));

            // Create a new db to ensure the user entities are recreated
            db = new IdentityDbContext();
            mgr = TestUtil.CreateManager(db);
            Assert.True(await mgr.IsLockedOutAsync(user.Id));
            var end = await mgr.GetLockoutEndDateAsync(user.Id);
            Assert.True(lockoutEnd.Subtract(end) < TimeSpan.FromSeconds(1)); // Conversions are slightly lossy
        }

        [Fact]
        public void UserLockedOutWithDateTimeNowPlus30Sync() {
            var mgr = TestUtil.CreateManager();
            mgr.UserLockoutEnabledByDefault = true;
            var user = new IdentityUser("LockoutTest");
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
        public async Task UserLockedOutWithDateTimeLocalKindNowPlus30() {
            var mgr = TestUtil.CreateManager();
            mgr.UserLockoutEnabledByDefault = true;
            var user = new IdentityUser("LockoutTest");
            UnitTestHelper.IsSuccess(mgr.Create(user));
            Assert.True(mgr.GetLockoutEnabled(user.Id));
            Assert.True(user.LockoutEnabled);
            var lockoutEnd = new DateTimeOffset(DateTime.Now.AddMinutes(30).ToLocalTime());
            UnitTestHelper.IsSuccess(await mgr.SetLockoutEndDateAsync(user.Id, lockoutEnd));
            Assert.True(await mgr.IsLockedOutAsync(user.Id));
            var end = await mgr.GetLockoutEndDateAsync(user.Id);
            Assert.Equal(lockoutEnd, end);
        }
    }
}