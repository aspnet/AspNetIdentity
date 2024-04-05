// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Data.Entity;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Xunit;
using Moq;

namespace Identity.Test
{
    public class UserManagerTest
    {
        [Fact]
        public void UsersQueryableFailWhenStoreNotImplementedTest()
        {
            var manager = new UserManager<IdentityUser>(new NoopUserStore());
            Assert.False(manager.SupportsQueryableUsers);
            Assert.Throws<NotSupportedException>(() => manager.Users.Count());
        }

        [Fact]
        public void UsersEmailMethodsFailWhenStoreNotImplementedTest()
        {
            var manager = new UserManager<IdentityUser>(new NoopUserStore());
            Assert.False(manager.SupportsUserEmail);
            Assert.Throws<NotSupportedException>(() => AsyncHelper.RunSync(() => manager.FindByEmailAsync(null)));
            Assert.Throws<NotSupportedException>(() => manager.FindByEmail(null));
            Assert.Throws<NotSupportedException>(() => AsyncHelper.RunSync(() => manager.SetEmailAsync(null, null)));
            Assert.Throws<NotSupportedException>(() => manager.SetEmail(null, null));
            Assert.Throws<NotSupportedException>(() => AsyncHelper.RunSync(() => manager.GetEmailAsync(null)));
            Assert.Throws<NotSupportedException>(() => manager.GetEmail(null));
            Assert.Throws<NotSupportedException>(() => AsyncHelper.RunSync(() => manager.IsEmailConfirmedAsync(null)));
            Assert.Throws<NotSupportedException>(() => manager.IsEmailConfirmed(null));
            Assert.Throws<NotSupportedException>(() => AsyncHelper.RunSync(() => manager.ConfirmEmailAsync(null, null)));
            Assert.Throws<NotSupportedException>(() => manager.ConfirmEmail(null, null));
        }

        [Fact]
        public void UsersPhoneNumberMethodsFailWhenStoreNotImplementedTest()
        {
            var manager = new UserManager<IdentityUser>(new NoopUserStore());
            Assert.False(manager.SupportsUserPhoneNumber);
            Assert.Throws<NotSupportedException>(
                () => AsyncHelper.RunSync(() => manager.SetPhoneNumberAsync(null, null)));
            Assert.Throws<NotSupportedException>(() => manager.SetPhoneNumber(null, null));
            Assert.Throws<NotSupportedException>(() => AsyncHelper.RunSync(() => manager.GetPhoneNumberAsync(null)));
            Assert.Throws<NotSupportedException>(() => manager.GetPhoneNumber(null));
        }

        [Fact]
        public void TokenMethodsThrowWithNoTokenProviderTest()
        {
            var manager = new UserManager<IdentityUser>(new NoopUserStore());
            Assert.Throws<NotSupportedException>(
                () => AsyncHelper.RunSync(() => manager.GenerateUserTokenAsync(null, null)));
            Assert.Throws<NotSupportedException>(
                () => AsyncHelper.RunSync(() => manager.VerifyUserTokenAsync(null, null, null)));
        }

        [Fact]
        public void PasswordMethodsFailWhenStoreNotImplementedTest()
        {
            var manager = new UserManager<IdentityUser>(new NoopUserStore());
            Assert.False(manager.SupportsUserPassword);
            Assert.Throws<NotSupportedException>(() => AsyncHelper.RunSync(() => manager.CreateAsync(null, null)));
            Assert.Throws<NotSupportedException>(
                () => AsyncHelper.RunSync(() => manager.ChangePasswordAsync(null, null, null)));
            Assert.Throws<NotSupportedException>(() => AsyncHelper.RunSync(() => manager.AddPasswordAsync(null, null)));
            Assert.Throws<NotSupportedException>(() => AsyncHelper.RunSync(() => manager.RemovePasswordAsync(null)));
            Assert.Throws<NotSupportedException>(() => AsyncHelper.RunSync(() => manager.CheckPasswordAsync(null, null)));
            Assert.Throws<NotSupportedException>(() => AsyncHelper.RunSync(() => manager.HasPasswordAsync(null)));
        }

        [Fact]
        public void SecurityStampMethodsFailWhenStoreNotImplementedTest()
        {
            var manager = new UserManager<IdentityUser>(new NoopUserStore());
            Assert.False(manager.SupportsUserSecurityStamp);
            Assert.Throws<NotSupportedException>(
                () => AsyncHelper.RunSync(() => manager.UpdateSecurityStampAsync("bogus")));
            Assert.Throws<NotSupportedException>(() => AsyncHelper.RunSync(() => manager.GetSecurityStampAsync("bogus")));
            Assert.Throws<NotSupportedException>(
                () => AsyncHelper.RunSync(() => manager.VerifyChangePhoneNumberTokenAsync("bogus", "1", "111-111-1111")));
            Assert.Throws<NotSupportedException>(
                () => AsyncHelper.RunSync(() => manager.GenerateChangePhoneNumberTokenAsync("bogus", "111-111-1111")));
        }

        [Fact]
        public void LoginMethodsFailWhenStoreNotImplementedTest()
        {
            var manager = new UserManager<IdentityUser>(new NoopUserStore());
            Assert.False(manager.SupportsUserLogin);
            Assert.Throws<NotSupportedException>(() => AsyncHelper.RunSync(() => manager.AddLoginAsync("bogus", null)));
            Assert.Throws<NotSupportedException>(
                () => AsyncHelper.RunSync(() => manager.RemoveLoginAsync("bogus", null)));
            Assert.Throws<NotSupportedException>(() => AsyncHelper.RunSync(() => manager.GetLoginsAsync("bogus")));
            Assert.Throws<NotSupportedException>(() => AsyncHelper.RunSync(() => manager.FindAsync(null)));
        }

        [Fact]
        public void ClaimMethodsFailWhenStoreNotImplementedTest()
        {
            var manager = new UserManager<IdentityUser>(new NoopUserStore());
            Assert.False(manager.SupportsUserClaim);
            Assert.Throws<NotSupportedException>(() => AsyncHelper.RunSync(() => manager.AddClaimAsync("bogus", null)));
            Assert.Throws<NotSupportedException>(
                () => AsyncHelper.RunSync(() => manager.RemoveClaimAsync("bogus", null)));
            Assert.Throws<NotSupportedException>(() => AsyncHelper.RunSync(() => manager.GetClaimsAsync("bogus")));
        }

        [Fact]
        public void TwoFactorStoreMethodsFailWhenStoreNotImplementedTest()
        {
            var manager = new UserManager<IdentityUser>(new NoopUserStore());
            Assert.False(manager.SupportsUserTwoFactor);
            Assert.Throws<NotSupportedException>(
                () => AsyncHelper.RunSync(() => manager.GetTwoFactorEnabledAsync("bogus")));
            Assert.Throws<NotSupportedException>(
                () => AsyncHelper.RunSync(() => manager.SetTwoFactorEnabledAsync("bogus", true)));
        }

        [Fact]
        public void RoleMethodsFailWhenStoreNotImplementedTest()
        {
            var manager = new UserManager<IdentityUser>(new NoopUserStore());
            Assert.False(manager.SupportsUserRole);
            Assert.Throws<NotSupportedException>(() => AsyncHelper.RunSync(() => manager.AddToRoleAsync("bogus", null)));
            Assert.Throws<NotSupportedException>(() => AsyncHelper.RunSync(() => manager.GetRolesAsync("bogus")));
            Assert.Throws<NotSupportedException>(
                () => AsyncHelper.RunSync(() => manager.RemoveFromRoleAsync("bogus", null)));
            Assert.Throws<NotSupportedException>(
                () => AsyncHelper.RunSync(() => manager.IsInRoleAsync("bogus", "bogus")));
        }

        [Fact]
        public void DisposeAfterDisposeWorksTest()
        {
            var manager = new UserManager<IdentityUser>(new UserStore<IdentityUser>());
            manager.Dispose();
            manager.Dispose();
        }

        [Fact]
        public void ManagerPublicNullCheckTest()
        {
            ExceptionHelper.ThrowsArgumentNull(() => new UserValidator<IdentityUser>(null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => new UserManager<IdentityUser>(null), "store");
            var manager = new UserManager<IdentityUser>(new UserStore<IdentityUser>());
            ExceptionHelper.ThrowsArgumentNull(
                () => AsyncHelper.RunSync(() => manager.UserValidator.ValidateAsync(null)), "item");
            ExceptionHelper.ThrowsArgumentNull(() => manager.ClaimsIdentityFactory = null, "value");
            ExceptionHelper.ThrowsArgumentNull(() => manager.UserValidator = null, "value");
            ExceptionHelper.ThrowsArgumentNull(() => manager.PasswordValidator = null, "value");
            ExceptionHelper.ThrowsArgumentNull(() => manager.PasswordHasher = null, "value");
            ExceptionHelper.ThrowsArgumentNull(
                () => AsyncHelper.RunSync(() => manager.CreateIdentityAsync(null, "whatever")), "user");
            ExceptionHelper.ThrowsArgumentNull(() => manager.CreateIdentity(null, "whatever"), "user");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => manager.CreateAsync(null)), "user");
            ExceptionHelper.ThrowsArgumentNull(() => manager.Create(null), "user");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => manager.CreateAsync(null, null)), "user");
            ExceptionHelper.ThrowsArgumentNull(() => manager.Create(null, null), "user");
            ExceptionHelper.ThrowsArgumentNull(
                () => AsyncHelper.RunSync(() => manager.CreateAsync(new IdentityUser(), null)), "password");
            ExceptionHelper.ThrowsArgumentNull(() => manager.Create(new IdentityUser(), null), "password");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => manager.UpdateAsync(null)), "user");
            ExceptionHelper.ThrowsArgumentNull(() => manager.Update(null), "user");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => manager.DeleteAsync(null)), "user");
            ExceptionHelper.ThrowsArgumentNull(() => manager.Delete(null), "user");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => manager.AddClaimAsync("bogus", null)),
                "claim");
            ExceptionHelper.ThrowsArgumentNull(() => manager.AddClaim("bogus", null), "claim");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => manager.FindByNameAsync(null)),
                "userName");
            ExceptionHelper.ThrowsArgumentNull(() => manager.FindByName(null), "userName");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => manager.FindAsync(null, null)),
                "userName");
            ExceptionHelper.ThrowsArgumentNull(() => manager.Find(null, null), "userName");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => manager.AddLoginAsync("bogus", null)),
                "login");
            ExceptionHelper.ThrowsArgumentNull(() => manager.AddLogin("bogus", null), "login");
            ExceptionHelper.ThrowsArgumentNull(
                () => AsyncHelper.RunSync(() => manager.RemoveLoginAsync("bogus", null)), "login");
            ExceptionHelper.ThrowsArgumentNull(() => manager.RemoveLogin("bogus", null), "login");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => manager.FindByEmailAsync(null)), "email");
            ExceptionHelper.ThrowsArgumentNull(() => manager.FindByEmail(null), "email");
            ExceptionHelper.ThrowsArgumentNull(() => manager.RegisterTwoFactorProvider(null, null), "twoFactorProvider");
            ExceptionHelper.ThrowsArgumentNull(() => manager.RegisterTwoFactorProvider("bogus", null), "provider");
        }

        [Fact]
        public void MethodsThrowWhenDisposedTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var manager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            manager.Dispose();
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => manager.AddClaimAsync("bogus", null)));
            Assert.Throws<ObjectDisposedException>(() => manager.AddClaim("bogus", null));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => manager.AddLoginAsync("bogus", null)));
            Assert.Throws<ObjectDisposedException>(() => manager.AddLogin("bogus", null));
            Assert.Throws<ObjectDisposedException>(
                () => AsyncHelper.RunSync(() => manager.AddPasswordAsync("bogus", null)));
            Assert.Throws<ObjectDisposedException>(() => manager.AddPassword("bogus", null));
            Assert.Throws<ObjectDisposedException>(
                () => AsyncHelper.RunSync(() => manager.AddToRoleAsync("bogus", null)));
            Assert.Throws<ObjectDisposedException>(() => manager.AddToRole("bogus", null));
            Assert.Throws<ObjectDisposedException>(
                () => AsyncHelper.RunSync(() => manager.AddToRolesAsync("bogus", null)));
            Assert.Throws<ObjectDisposedException>(() => manager.AddToRoles("bogus", null));
            Assert.Throws<ObjectDisposedException>(
                () => AsyncHelper.RunSync(() => manager.ChangePasswordAsync("bogus", null, null)));
            Assert.Throws<ObjectDisposedException>(() => manager.ChangePassword("bogus", null, null));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => manager.GetClaimsAsync("bogus")));
            Assert.Throws<ObjectDisposedException>(() => manager.GetClaims("bogus"));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => manager.GetLoginsAsync("bogus")));
            Assert.Throws<ObjectDisposedException>(() => manager.GetLogins("bogus"));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => manager.GetRolesAsync("bogus")));
            Assert.Throws<ObjectDisposedException>(() => manager.GetRoles("bogus"));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => manager.IsInRoleAsync("bogus", null)));
            Assert.Throws<ObjectDisposedException>(() => manager.IsInRole("bogus", null));
            Assert.Throws<ObjectDisposedException>(
                () => AsyncHelper.RunSync(() => manager.RemoveClaimAsync("bogus", null)));
            Assert.Throws<ObjectDisposedException>(() => manager.RemoveClaim("bogus", null));
            Assert.Throws<ObjectDisposedException>(
                () => AsyncHelper.RunSync(() => manager.RemoveLoginAsync("bogus", null)));
            Assert.Throws<ObjectDisposedException>(() => manager.RemoveLogin("bogus", null));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => manager.RemovePasswordAsync("bogus")));
            Assert.Throws<ObjectDisposedException>(() => manager.RemovePassword("bogus"));
            Assert.Throws<ObjectDisposedException>(
                () => AsyncHelper.RunSync(() => manager.RemoveFromRoleAsync("bogus", null)));
            Assert.Throws<ObjectDisposedException>(() => manager.RemoveFromRole("bogus", null));
            Assert.Throws<ObjectDisposedException>(
                () => AsyncHelper.RunSync(() => manager.RemoveFromRolesAsync("bogus", null)));
            Assert.Throws<ObjectDisposedException>(() => manager.RemoveFromRoles("bogus", null));
            Assert.Throws<ObjectDisposedException>(
                () => AsyncHelper.RunSync(() => manager.RemoveClaimAsync("bogus", null)));
            Assert.Throws<ObjectDisposedException>(() => manager.RemoveClaim("bogus", null));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => manager.FindAsync("bogus", null)));
            Assert.Throws<ObjectDisposedException>(() => manager.Find("bogus", null));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => manager.FindAsync(null)));
            Assert.Throws<ObjectDisposedException>(() => manager.Find(null));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => manager.FindByIdAsync(null)));
            Assert.Throws<ObjectDisposedException>(() => manager.FindById(null));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => manager.FindByNameAsync(null)));
            Assert.Throws<ObjectDisposedException>(() => manager.FindByName(null));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => manager.CreateAsync(null)));
            Assert.Throws<ObjectDisposedException>(() => manager.Create(null));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => manager.CreateAsync(null, null)));
            Assert.Throws<ObjectDisposedException>(() => manager.Create(null, null));
            Assert.Throws<ObjectDisposedException>(
                () => AsyncHelper.RunSync(() => manager.CreateIdentityAsync(null, null)));
            Assert.Throws<ObjectDisposedException>(() => manager.CreateIdentity(null, null));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => manager.UpdateAsync(null)));
            Assert.Throws<ObjectDisposedException>(() => manager.Update(null));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => manager.DeleteAsync(null)));
            Assert.Throws<ObjectDisposedException>(() => manager.Delete(null));
            Assert.Throws<ObjectDisposedException>(
                () => AsyncHelper.RunSync(() => manager.UpdateSecurityStampAsync(null)));
            Assert.Throws<ObjectDisposedException>(() => manager.UpdateSecurityStamp(null));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => manager.GetSecurityStampAsync(null)));
            Assert.Throws<ObjectDisposedException>(() => manager.GetSecurityStamp(null));
            Assert.Throws<ObjectDisposedException>(
                () => AsyncHelper.RunSync(() => manager.GeneratePasswordResetTokenAsync(null)));
            Assert.Throws<ObjectDisposedException>(() => manager.GeneratePasswordResetToken(null));
            Assert.Throws<ObjectDisposedException>(
                () => AsyncHelper.RunSync(() => manager.ResetPasswordAsync(null, null, null)));
            Assert.Throws<ObjectDisposedException>(() => manager.ResetPassword(null, null, null));
            Assert.Throws<ObjectDisposedException>(
                () => AsyncHelper.RunSync(() => manager.GenerateEmailConfirmationTokenAsync(null)));
            Assert.Throws<ObjectDisposedException>(() => manager.GenerateEmailConfirmationToken(null));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => manager.IsEmailConfirmedAsync(null)));
            Assert.Throws<ObjectDisposedException>(() => manager.IsEmailConfirmed(null));
            Assert.Throws<ObjectDisposedException>(
                () => AsyncHelper.RunSync(() => manager.ConfirmEmailAsync(null, null)));
            Assert.Throws<ObjectDisposedException>(() => manager.ConfirmEmail(null, null));
        }

        [Fact]
        public void SyncManagerNullCheckTest()
        {
            UserManager<IdentityUser> manager = null;
            ExceptionHelper.ThrowsArgumentNull(() => manager.AddClaim("bogus", null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.AddLogin("bogus", null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.AddPassword("bogus", null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.AddToRole("bogus", null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.AddToRoles("bogus", null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.ChangePassword("bogus", null, null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.HasPassword("bogus"), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.GetClaims("bogus"), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.GetLogins("bogus"), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.GetRoles("bogus"), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.IsInRole("bogus", null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.RemoveClaim("bogus", null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.RemoveLogin("bogus", null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.RemovePassword("bogus"), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.RemoveFromRole("bogus", null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.RemoveFromRoles("bogus", null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.RemoveClaim("bogus", null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.Find("bogus", null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.Find(null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.FindById(null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.FindByName(null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.Create(null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.Create(null, null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.CreateIdentity(null, null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.Update(null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.Delete(null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.UpdateSecurityStamp(null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.GetSecurityStamp(null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.IsEmailConfirmed(null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.ConfirmEmail(null, null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.GeneratePasswordResetToken(null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.ResetPassword(null, null, null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.FindByEmail(null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.GetEmail(null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.SetEmail(null, null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.GenerateEmailConfirmationToken(null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.GenerateTwoFactorToken(null, null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.VerifyTwoFactorToken(null, null, null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.GetValidTwoFactorProviders(null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.GetPhoneNumber(null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.SetPhoneNumber(null, null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.IsPhoneNumberConfirmed(null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.ChangePhoneNumber(null, null, null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.VerifyChangePhoneNumberToken(null, null, null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.GenerateUserToken(null, null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.VerifyUserToken(null, null, null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.GetTwoFactorEnabled(null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.SetTwoFactorEnabled(null, true), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.SetLockoutEnabled(null, true), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.GetLockoutEnabled(null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.IsLockedOut(null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.SetLockoutEndDate(null, DateTimeOffset.UtcNow), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.GetLockoutEndDate(null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.AccessFailed(null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.GetAccessFailedCount(null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.ResetAccessFailedCount(null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.CheckPassword(null, null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.GenerateChangePhoneNumberToken(null, null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.NotifyTwoFactorToken(null, null, null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.SendSms(null, null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.SendEmail(null, null, null), "manager");
        }

        [Fact]
        public void IdentityContextWithNullDbContextThrowsTest()
        {
            ExceptionHelper.ThrowsArgumentNull(() => new UserStore<IdentityUser>(null), "context");
        }

        [Fact]
        public async Task PasswordLengthSuccessValidatorTest()
        {
            var validator = new MinimumLengthValidator(1);
            var result = await validator.ValidateAsync("11");
            UnitTestHelper.IsSuccess(result);
        }

        [Fact]
        public async Task PasswordTooShortValidatorTest()
        {
            var manager = new UserManager<IdentityUser>(new UserStore<IdentityUser>());
            UnitTestHelper.IsFailure(await manager.CreateAsync(new IdentityUser("Hao"), "11"),
                "Passwords must be at least 6 characters.");
        }

        private class NoopUserStore : IUserStore<IdentityUser>
        {
            public Task CreateAsync(IdentityUser user)
            {
                return Task.FromResult(0);
            }

            public Task UpdateAsync(IdentityUser user)
            {
                return Task.FromResult(0);
            }

            public Task<IdentityUser> FindByIdAsync(string userId)
            {
                return Task.FromResult<IdentityUser>(null);
            }

            public Task<IdentityUser> FindByNameAsync(string userName)
            {
                return Task.FromResult<IdentityUser>(null);
            }

            public void Dispose()
            {
            }

            public Task DeleteAsync(IdentityUser user)
            {
                return Task.FromResult(0);
            }
        }
    }
}