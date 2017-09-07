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
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security.DataProtection;
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
        public void MethodsFailWithUnknownUserTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var manager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            manager.UserTokenProvider = new NoOpTokenProvider();
            var error = "UserId not found.";
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.AddClaimAsync(null, new Claim("a", "b"))), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.AddLoginAsync(null, new UserLoginInfo("", ""))), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.AddPasswordAsync(null, null)), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.AddToRoleAsync(null, null)), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.AddToRolesAsync(null, "")), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.ChangePasswordAsync(null, null, null)), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.GetClaimsAsync(null)), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.GetLoginsAsync(null)), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.GetRolesAsync(null)), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.IsInRoleAsync(null, null)), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.RemoveClaimAsync(null, new Claim("a", "b"))), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.RemoveLoginAsync(null, new UserLoginInfo("", ""))), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.RemovePasswordAsync(null)), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.RemoveFromRoleAsync(null, null)), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.RemoveFromRolesAsync(null, "")), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.UpdateSecurityStampAsync(null)), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.GetSecurityStampAsync(null)), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.HasPasswordAsync(null)), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.GeneratePasswordResetTokenAsync(null)), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.ResetPasswordAsync(null, null, null)), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.IsEmailConfirmedAsync(null)), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.GenerateEmailConfirmationTokenAsync(null)), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.ConfirmEmailAsync(null, null)), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.GetEmailAsync(null)), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.SetEmailAsync(null, null)), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.IsPhoneNumberConfirmedAsync(null)), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.ChangePhoneNumberAsync(null, null, null)), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.VerifyChangePhoneNumberTokenAsync(null, null, null)), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.GetPhoneNumberAsync(null)), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.SetPhoneNumberAsync(null, null)), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.GetTwoFactorEnabledAsync(null)), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.SetTwoFactorEnabledAsync(null, true)), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.GenerateTwoFactorTokenAsync(null, null)), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.VerifyTwoFactorTokenAsync(null, null, null)), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.NotifyTwoFactorTokenAsync(null, null, null)), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.GetValidTwoFactorProvidersAsync(null)), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.VerifyUserTokenAsync(null, null, null)), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.AccessFailedAsync(null)), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.SetLockoutEnabledAsync(null, false)), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.SetLockoutEndDateAsync(null, DateTimeOffset.UtcNow)), error);
            ExceptionHelper.ThrowsWithError<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.IsLockedOutAsync(null)), error);
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

        [Fact]
        public async Task CustomPasswordValidatorTest()
        {
            var manager = TestUtil.CreateManager();
            manager.PasswordValidator = new AlwaysBadValidator<String>();
            UnitTestHelper.IsFailure(await manager.CreateAsync(new IdentityUser("Hao"), "password"),
                AlwaysBadValidator<String>.ErrorMessage);
        }

        [Fact]
        public async Task PasswordValidatorTest()
        {
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("passwordValidator");
            manager.PasswordValidator = new PasswordValidator { RequiredLength = 6, RequireNonLetterOrDigit = true };
            const string alphaError = "Passwords must have at least one non letter or digit character.";
            const string lengthError = "Passwords must be at least 6 characters.";
            UnitTestHelper.IsFailure(await manager.CreateAsync(user, "ab@de"), lengthError);
            UnitTestHelper.IsFailure(await manager.CreateAsync(user, "abcdef"), alphaError);
            UnitTestHelper.IsFailure(await manager.CreateAsync(user, "___"), lengthError);
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user, "abcd@e!ld!kajfd"));
            UnitTestHelper.IsFailure(await manager.CreateAsync(user, "abcde"), lengthError + " " + alphaError);
        }

        [Fact]
        public async Task CustomPasswordValidatorBlocksAddPasswordTest()
        {
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("test");
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            manager.PasswordValidator = new AlwaysBadValidator<String>();
            UnitTestHelper.IsFailure(await manager.AddPasswordAsync(user.Id, "password"),
                AlwaysBadValidator<String>.ErrorMessage);
        }

        [Fact]
        public async Task CustomUserNameValidatorTest()
        {
            var manager = TestUtil.CreateManager();
            manager.UserValidator = new AlwaysBadValidator<IdentityUser>();
            var result = await manager.CreateAsync(new IdentityUser("Hao"));
            UnitTestHelper.IsFailure(result, AlwaysBadValidator<IdentityUser>.ErrorMessage);
        }

        [Fact]
        public async Task BadValidatorBlocksAllUpdatesTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var manager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            var user = new IdentityUser("poorguy");
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            const string error = AlwaysBadValidator<IdentityUser>.ErrorMessage;
            manager.UserValidator = new AlwaysBadValidator<IdentityUser>();
            manager.PasswordValidator = new NoopValidator<string>();
            UnitTestHelper.IsFailure(await manager.AddClaimAsync(user.Id, new Claim("a", "b")), error);
            UnitTestHelper.IsFailure(await manager.AddLoginAsync(user.Id, new UserLoginInfo("", "")), error);
            UnitTestHelper.IsFailure(await manager.AddPasswordAsync(user.Id, "a"), error);
            UnitTestHelper.IsFailure(await manager.ChangePasswordAsync(user.Id, "a", "b"), error);
            UnitTestHelper.IsFailure(await manager.RemoveClaimAsync(user.Id, new Claim("a", "b")), error);
            UnitTestHelper.IsFailure(await manager.RemoveLoginAsync(user.Id, new UserLoginInfo("aa", "bb")), error);
            UnitTestHelper.IsFailure(await manager.RemovePasswordAsync(user.Id), error);
            UnitTestHelper.IsFailure(await manager.UpdateSecurityStampAsync(user.Id), error);
        }

        [Fact]
        public async Task CreateLocalUserWithOnlyWhitespaceUserNameFails()
        {
            var manager = new UserManager<IdentityUser>(new UserStore<IdentityUser>());
            var result = await manager.CreateAsync(new IdentityUser { UserName = " " }, "password");
            UnitTestHelper.IsFailure(result, "Name cannot be null or empty.");
        }

        [Fact]
        public async Task CreateLocalUserWithInvalidUserNameFails()
        {
            var manager = TestUtil.CreateManager();
            var result = await manager.CreateAsync(new IdentityUser { UserName = "a\0b" }, "password");
            UnitTestHelper.IsFailure(result, "User name a\0b is invalid, can only contain letters or digits.");
        }

        [Fact]
        public async Task CreateLocalUserWithInvalidPasswordThrows()
        {
            var manager = TestUtil.CreateManager();
            var result = await manager.CreateAsync(new IdentityUser("Hao"), "aa");
            UnitTestHelper.IsFailure(result, "Passwords must be at least 6 characters.");
        }

        [Fact]
        public async Task CreateExternalUserWithNullFails()
        {
            var manager = TestUtil.CreateManager();
            UnitTestHelper.IsFailure(await manager.CreateAsync(new IdentityUser { UserName = null }),
                "Name cannot be null or empty.");
        }

        [Fact]
        public async Task AddPasswordWhenPasswordSetFails()
        {
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("HasPassword");
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user, "password"));
            UnitTestHelper.IsFailure(await manager.AddPasswordAsync(user.Id, "User already has a password."));
        }

        private async Task LazyLoadTestSetup(DbContext db, IdentityUser user)
        {
            var manager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            var role = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(db));
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            UnitTestHelper.IsSuccess(await manager.AddLoginAsync(user.Id, new UserLoginInfo("provider", "key")));
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
        }

        [Fact]
        public async Task LazyLoadDisabledFindByIdTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var user = new IdentityUser("Hao");
            user.Email = "hao@foo.com";
            await LazyLoadTestSetup(db, user);

            // Ensure lazy loading is not broken
            db = new IdentityDbContext();
            db.Configuration.LazyLoadingEnabled = false;
            db.Configuration.ProxyCreationEnabled = false;
            var manager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            var userById = await manager.FindByIdAsync(user.Id);
            Assert.True(userById.Claims.Count == 2);
            Assert.True(userById.Logins.Count == 1);
            Assert.True(userById.Roles.Count == 2);
        }

        [Fact]
        public async Task LazyLoadDisabledFindByNameTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var user = new IdentityUser("Hao") { Email = "hao@foo.com" };
            await LazyLoadTestSetup(db, user);

            // Ensure lazy loading is not broken
            db = new IdentityDbContext();
            db.Configuration.LazyLoadingEnabled = false;
            db.Configuration.ProxyCreationEnabled = false;
            var manager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            var userByName = await manager.FindByNameAsync(user.UserName);
            Assert.True(userByName.Claims.Count == 2);
            Assert.True(userByName.Logins.Count == 1);
            Assert.True(userByName.Roles.Count == 2);
        }

        [Fact]
        public async Task LazyLoadDisabledFindByLoginTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var user = new IdentityUser("Hao") { Email = "hao@foo.com" };
            await LazyLoadTestSetup(db, user);

            // Ensure lazy loading is not broken
            db = new IdentityDbContext();
            db.Configuration.LazyLoadingEnabled = false;
            db.Configuration.ProxyCreationEnabled = false;
            var manager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            var userByLogin = await manager.FindAsync(new UserLoginInfo("provider", "key"));
            Assert.True(userByLogin.Claims.Count == 2);
            Assert.True(userByLogin.Logins.Count == 1);
            Assert.True(userByLogin.Roles.Count == 2);
        }

        [Fact]
        public async Task LazyLoadDisabledFindByEmailTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var user = new IdentityUser("Hao") { Email = "hao@foo.com" };
            await LazyLoadTestSetup(db, user);

            // Ensure lazy loading is not broken
            db = new IdentityDbContext();
            db.Configuration.LazyLoadingEnabled = false;
            db.Configuration.ProxyCreationEnabled = false;
            var manager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            var userByEmail = await manager.FindByEmailAsync(user.Email);
            Assert.True(userByEmail.Claims.Count == 2);
            Assert.True(userByEmail.Logins.Count == 1);
            Assert.True(userByEmail.Roles.Count == 2);
        }

        [Fact]
        public async Task FindNullIdTest()
        {
            var manager = TestUtil.CreateManager();
            Assert.Null(await manager.FindByIdAsync(null));
        }

        [Fact]
        public async Task CreateLocalUserTest()
        {
            var manager = TestUtil.CreateManager();
            const string password = "password";
            UnitTestHelper.IsSuccess(await manager.CreateAsync(new IdentityUser("CreateLocalUserTest"), password));
            var user = await manager.FindByNameAsync("CreateLocalUserTest");
            Assert.NotNull(user);
            Assert.NotNull(user.PasswordHash);
            Assert.True(await manager.HasPasswordAsync(user.Id));
            var logins = await manager.GetLoginsAsync(user.Id);
            Assert.NotNull(logins);
            Assert.Equal(0, logins.Count());
        }

        [Fact]
        public void CreateLocalUserTestSync()
        {
            var manager = TestUtil.CreateManager();
            const string password = "password";
            UnitTestHelper.IsSuccess(manager.Create(new IdentityUser("CreateLocalUserTest"), password));
            var user = manager.FindByName("CreateLocalUserTest");
            Assert.NotNull(user);
            Assert.NotNull(user.PasswordHash);
            Assert.True(manager.HasPassword(user.Id));
            var logins = manager.GetLogins(user.Id);
            Assert.NotNull(logins);
            Assert.Equal(0, logins.Count());
        }

        [Fact]
        public async Task DeleteUserTest()
        {
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("Delete");
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            UnitTestHelper.IsSuccess(await manager.DeleteAsync(user));
            Assert.Null(await manager.FindByIdAsync(user.Id));
        }

        [Fact]
        public void DeleteUserSyncTest()
        {
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("Delete");
            UnitTestHelper.IsSuccess(manager.Create(user));
            UnitTestHelper.IsSuccess(manager.Delete(user));
            Assert.Null(manager.FindById(user.Id));
        }

        [Fact]
        public async Task CreateUserAddLoginTest()
        {
            var manager = TestUtil.CreateManager();
            const string userName = "CreateExternalUserTest";
            const string provider = "ZzAuth";
            const string providerKey = "HaoKey";
            UnitTestHelper.IsSuccess(await manager.CreateAsync(new IdentityUser(userName)));
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
            var manager = TestUtil.CreateManager();
            const string userName = "CreateExternalUserTest";
            const string provider = "ZzAuth";
            const string providerKey = "HaoKey";
            UnitTestHelper.IsSuccess(manager.Create(new IdentityUser(userName)));
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
            var manager = TestUtil.CreateManager();
            var login = new UserLoginInfo("Provider", "key");
            var user = new IdentityUser("CreateUserLoginAddPasswordTest");
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            UnitTestHelper.IsSuccess(await manager.AddLoginAsync(user.Id, login));
            UnitTestHelper.IsSuccess(await manager.AddPasswordAsync(user.Id, "password"));
            var logins = await manager.GetLoginsAsync(user.Id);
            Assert.NotNull(logins);
            Assert.Equal(1, logins.Count());
            Assert.Equal(user, await manager.FindAsync(login));
            Assert.Equal(user, await manager.FindAsync(user.UserName, "password"));
            Assert.True(await manager.CheckPasswordAsync(user, "password"));
        }

        [Fact]
        public void CreateUserLoginAndAddPasswordSyncTest()
        {
            var manager = TestUtil.CreateManager();
            var login = new UserLoginInfo("Provider", "key");
            var user = new IdentityUser("CreateUserLoginAddPasswordTest");
            UnitTestHelper.IsSuccess(manager.Create(user));
            UnitTestHelper.IsSuccess(manager.AddLogin(user.Id, login));
            UnitTestHelper.IsSuccess(manager.AddPassword(user.Id, "password"));
            var logins = manager.GetLogins(user.Id);
            Assert.NotNull(logins);
            Assert.Equal(1, logins.Count());
            Assert.Equal(user, manager.Find(login));
            Assert.Equal(user, manager.Find(user.UserName, "password"));
            Assert.True(manager.CheckPassword(user, "password"));
        }

        [Fact]
        public async Task CreateUserAddRemoveLoginTest()
        {
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("CreateUserAddRemoveLoginTest");
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
            var stamp = await manager.GetSecurityStampAsync(user.Id);
            UnitTestHelper.IsSuccess(await manager.RemoveLoginAsync(user.Id, login));
            Assert.Null(await manager.FindAsync(login));
            logins = await manager.GetLoginsAsync(user.Id);
            Assert.NotNull(logins);
            Assert.Equal(0, logins.Count());
            Assert.NotEqual(stamp, user.SecurityStamp);
        }

        [Fact]
        public void CreateUserAddRemoveLoginSyncTest()
        {
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("CreateUserAddRemoveLoginTest");
            var login = new UserLoginInfo("Provider", "key");
            const string password = "password";
            var result = manager.Create(user, password);
            Assert.NotNull(user);
            UnitTestHelper.IsSuccess(result);
            UnitTestHelper.IsSuccess(manager.AddLogin(user.Id, login));
            Assert.Equal(user, manager.Find(login));
            var logins = manager.GetLogins(user.Id);
            Assert.NotNull(logins);
            Assert.Equal(1, logins.Count());
            Assert.Equal(login.LoginProvider, logins.Last().LoginProvider);
            Assert.Equal(login.ProviderKey, logins.Last().ProviderKey);
            var stamp = manager.GetSecurityStamp(user.Id);
            UnitTestHelper.IsSuccess(manager.RemoveLogin(user.Id, login));
            Assert.Null(manager.Find(login));
            logins = manager.GetLogins(user.Id);
            Assert.NotNull(logins);
            Assert.Equal(0, logins.Count());
            Assert.NotEqual(stamp, user.SecurityStamp);
        }

        [Fact]
        public async Task RemovePasswordTest()
        {
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("RemovePasswordTest");
            const string password = "password";
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user, password));
            var stamp = await manager.GetSecurityStampAsync(user.Id);
            UnitTestHelper.IsSuccess(await manager.RemovePasswordAsync(user.Id));
            var u = await manager.FindByNameAsync(user.UserName);
            Assert.NotNull(u);
            Assert.Null(u.PasswordHash);
            Assert.NotEqual(stamp, user.SecurityStamp);
        }

        [Fact]
        public void RemovePasswordSyncTest()
        {
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("RemovePasswordTest");
            const string password = "password";
            UnitTestHelper.IsSuccess(manager.Create(user, password));
            var stamp = manager.GetSecurityStamp(user.Id);
            UnitTestHelper.IsSuccess(manager.RemovePassword(user.Id));
            var u = manager.FindByName(user.UserName);
            Assert.NotNull(u);
            Assert.Null(u.PasswordHash);
            Assert.NotEqual(stamp, user.SecurityStamp);
        }

        [Fact]
        public async Task ChangePasswordTest()
        {
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("ChangePasswordTest");
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
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("ChangePasswordTest");
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
        public async Task ResetPasswordTest()
        {
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("ResetPasswordTest");
            const string password = "password";
            const string newPassword = "newpassword";
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user, password));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = await manager.GeneratePasswordResetTokenAsync(user.Id);
            Assert.NotNull(token);
            UnitTestHelper.IsSuccess(await manager.ResetPasswordAsync(user.Id, token, newPassword));
            Assert.Null(await manager.FindAsync(user.UserName, password));
            Assert.Equal(user, await manager.FindAsync(user.UserName, newPassword));
            Assert.NotEqual(stamp, user.SecurityStamp);
        }

        [Fact]
        public async Task ResetPasswordWithNoStampTest()
        {
            var manager = new NoStampUserManager();
            var user = new IdentityUser("ResetPasswordTest");
            const string password = "password";
            const string newPassword = "newpassword";
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user, password));
            var token = await manager.GeneratePasswordResetTokenAsync(user.Id);
            Assert.NotNull(token);
            UnitTestHelper.IsSuccess(await manager.ResetPasswordAsync(user.Id, token, newPassword));
            Assert.Null(await manager.FindAsync(user.UserName, password));
            Assert.Equal(user, await manager.FindAsync(user.UserName, newPassword));
        }

        [Fact]
        public async Task GenerateUserTokenTest()
        {
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("UserTokenTest");
            var user2 = new IdentityUser("UserTokenTest2");
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user2));
            var token = await manager.GenerateUserTokenAsync("test", user.Id);
            Assert.True(await manager.VerifyUserTokenAsync(user.Id, "test", token));
            Assert.False(await manager.VerifyUserTokenAsync(user.Id, "test2", token));
            Assert.False(await manager.VerifyUserTokenAsync(user.Id, "test", token + "a"));
            Assert.False(await manager.VerifyUserTokenAsync(user2.Id, "test", token));
        }

        [Fact]
        public void GenerateUserTokenSyncTest()
        {
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("UserTokenTest");
            var user2 = new IdentityUser("UserTokenTest2");
            UnitTestHelper.IsSuccess(manager.Create(user));
            UnitTestHelper.IsSuccess(manager.Create(user2));
            var token = manager.GenerateUserToken("test", user.Id);
            Assert.True(manager.VerifyUserToken(user.Id, "test", token));
            Assert.False(manager.VerifyUserToken(user.Id, "test2", token));
            Assert.False(manager.VerifyUserToken(user.Id, "test", token + "a"));
            Assert.False(manager.VerifyUserToken(user2.Id, "test", token));
        }

        [Fact]
        public async Task GetTwoFactorEnabledTest()
        {
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("TwoFactorEnabledTest");
            UnitTestHelper.IsSuccess(manager.Create(user));
            Assert.False(await manager.GetTwoFactorEnabledAsync(user.Id));
            UnitTestHelper.IsSuccess(await manager.SetTwoFactorEnabledAsync(user.Id, true));
            Assert.True(await manager.GetTwoFactorEnabledAsync(user.Id));
            UnitTestHelper.IsSuccess(await manager.SetTwoFactorEnabledAsync(user.Id, false));
            Assert.False(await manager.GetTwoFactorEnabledAsync(user.Id));
        }

        [Fact]
        public void GetTwoFactorEnabledSyncTest()
        {
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("TwoFactorEnabledTest");
            UnitTestHelper.IsSuccess(manager.Create(user));
            Assert.False(manager.GetTwoFactorEnabled(user.Id));
            UnitTestHelper.IsSuccess(manager.SetTwoFactorEnabled(user.Id, true));
            Assert.True(manager.GetTwoFactorEnabled(user.Id));
            UnitTestHelper.IsSuccess(manager.SetTwoFactorEnabled(user.Id, false));
            Assert.False(manager.GetTwoFactorEnabled(user.Id));
        }

        [Fact]
        public async Task ResetPasswordWithConfirmTokenFailsTest()
        {
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("ResetPasswordTest");
            var password = "password";
            var newPassword = "newpassword";
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user, password));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = await manager.GenerateEmailConfirmationTokenAsync(user.Id);
            Assert.NotNull(token);
            UnitTestHelper.IsFailure(await manager.ResetPasswordAsync(user.Id, token, newPassword));
            Assert.Null(await manager.FindAsync(user.UserName, newPassword));
            Assert.Equal(user, await manager.FindAsync(user.UserName, password));
            Assert.Equal(stamp, user.SecurityStamp);
        }

        [Fact]
        public async Task ResetPasswordWithExpiredTokenFailsTest()
        {
            var manager = TestUtil.CreateManager();
            var provider = new DpapiDataProtectionProvider();
            //manager.PasswordResetTokens = new DataProtectorTokenProvider<IdentityUser>(provider.Create("ResetPassword")) { TokenLifespan = TimeSpan.FromTicks(0) };
            manager.UserTokenProvider = new DataProtectorTokenProvider<IdentityUser>(provider.Create("ResetPassword"))
            {
                TokenLifespan = TimeSpan.FromTicks(0)
            };
            var user = new IdentityUser("ResetPasswordTest");
            var password = "password";
            var newPassword = "newpassword";
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user, password));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = await manager.GeneratePasswordResetTokenAsync(user.Id);
            Assert.NotNull(token);
            Thread.Sleep(10);
            UnitTestHelper.IsFailure(await manager.ResetPasswordAsync(user.Id, token, newPassword));
            Assert.Null(await manager.FindAsync(user.UserName, newPassword));
            Assert.Equal(user, await manager.FindAsync(user.UserName, password));
            Assert.Equal(stamp, user.SecurityStamp);
        }

        [Fact]
        public void ResetPasswordSyncTest()
        {
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("ResetPasswordTest");
            var password = "password";
            var newPassword = "newpassword";
            UnitTestHelper.IsSuccess(manager.Create(user, password));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = manager.GeneratePasswordResetToken(user.Id);
            Assert.NotNull(token);
            UnitTestHelper.IsSuccess(manager.ResetPassword(user.Id, token, newPassword));
            Assert.Null(manager.Find(user.UserName, password));
            Assert.Equal(user, manager.Find(user.UserName, newPassword));
            Assert.NotEqual(stamp, user.SecurityStamp);
        }

        [Fact]
        public async Task ResetPasswordFailsWithWrongTokenTest()
        {
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("ResetPasswordTest");
            var password = "password";
            var newPassword = "newpassword";
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user, password));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            UnitTestHelper.IsFailure(await manager.ResetPasswordAsync(user.Id, "bogus", newPassword), "Invalid token.");
            Assert.Null(await manager.FindAsync(user.UserName, newPassword));
            Assert.Equal(user, await manager.FindAsync(user.UserName, password));
            Assert.Equal(stamp, user.SecurityStamp);
        }

        [Fact]
        public async Task ResetPasswordFailsAfterPasswordChangeTest()
        {
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("ResetPasswordTest");
            var password = "password";
            var newPassword = "newpassword";
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user, password));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = manager.GeneratePasswordResetToken(user.Id);
            Assert.NotNull(token);
            UnitTestHelper.IsSuccess(await manager.ChangePasswordAsync(user.Id, password, "bogus1"));
            UnitTestHelper.IsFailure(await manager.ResetPasswordAsync(user.Id, token, newPassword), "Invalid token.");
            Assert.Null(await manager.FindAsync(user.UserName, newPassword));
            Assert.Equal(user, await manager.FindAsync(user.UserName, "bogus1"));
        }

        [Fact]
        public async Task AddRemoveUserClaimTest()
        {
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("ClaimsAddRemove");
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            Claim[] claims = { new Claim("c", "v"), new Claim("c2", "v2"), new Claim("c2", "v3") };
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
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("ClaimsAddRemove");
            UnitTestHelper.IsSuccess(manager.Create(user));
            Claim[] claims = { new Claim("c", "v"), new Claim("c2", "v2"), new Claim("c2", "v3") };
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
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("user");
            var password = "password";
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user, password));
            var result = await manager.ChangePasswordAsync(user.Id, password, "n");
            UnitTestHelper.IsFailure(result, "Passwords must be at least 6 characters.");
        }

        [Fact]
        public async Task ChangePasswordFallsIfPasswordWrongTest()
        {
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("user");
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user, "password"));
            var result = await manager.ChangePasswordAsync(user.Id, "bogus", "newpassword");
            UnitTestHelper.IsFailure(result, "Incorrect password.");
        }

        [Fact]
        public void ChangePasswordFallsIfPasswordWrongSyncTest()
        {
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("user");
            UnitTestHelper.IsSuccess(manager.Create(user, "password"));
            var result = manager.ChangePassword(user.Id, "bogus", "newpassword");
            UnitTestHelper.IsFailure(result, "Incorrect password.");
        }

        [Fact]
        public async Task CanRelaxUserNameAndPasswordValidationTest()
        {
            var manager = TestUtil.CreateManager();
            manager.UserValidator = new UserValidator<IdentityUser>(manager) { AllowOnlyAlphanumericUserNames = false };
            manager.PasswordValidator = new MinimumLengthValidator(1);
            UnitTestHelper.IsSuccess(await manager.CreateAsync(new IdentityUser("Some spaces"), "pwd"));
        }

        [Fact]
        public async Task CanUseEmailAsUserNameTest()
        {
            var manager = TestUtil.CreateManager();
            UnitTestHelper.IsSuccess(await manager.CreateAsync(new IdentityUser("test_email@foo.com")));
        }

        [Fact]
        public async Task AddDupeUserFailsTest()
        {
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("dupe");
            var user2 = new IdentityUser("dupe");
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            UnitTestHelper.IsFailure(await manager.CreateAsync(user2), "Name dupe is already taken.");
        }

        [Fact]
        public async Task FindWithPasswordUnknownUserReturnsNullTest()
        {
            var manager = TestUtil.CreateManager();
            Assert.Null(await manager.FindAsync("bogus", "sdlkfsadf"));
            Assert.Null(manager.Find("bogus", "sdlkfsadf"));
        }

        [Fact]
        public async Task UpdateSecurityStampTest()
        {
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("stampMe");
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
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("stampMe");
            Assert.Null(user.SecurityStamp);
            UnitTestHelper.IsSuccess(manager.Create(user));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            UnitTestHelper.IsSuccess(manager.UpdateSecurityStamp(user.Id));
            Assert.NotEqual(stamp, user.SecurityStamp);
        }

        //[Fact]
        //public async Task AddPasswordToUnknownUserFailsTest() {
        //    UnitTestHelper.IsFailure(await CreateManager().Users.UpdatePasswordAsync("bogus", "password"), "User bogus does not exist.");
        //}

        //[Fact]
        //public async Task CreateLocalUserNameTooLongThrowsTest() {
        //    var manager = CreateManager();
        //    var userNameTooLong = new IdentityUser("baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        //    var result = await manager.CreateAsync(userNameTooLong, "password");
        //    Assert.False(result.Succeeded);
        //    Assert.True(result.Errors.First().Contains("maximum length")); // Should say something about max length in the error msg
        //}

        ////[Fact]
        ////public async Task CreateExternalUserNameTooLongThrowsTest() {
        ////    IdentityStoreContext noop = CreateManagerSync();
        ////    string userNameTooLong = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        ////    ExceptionHelper.ExpectException<IdentityException>(() => AsyncHelper.RunSync(() => context.CreateWithLoginAsync(new IdentityUser(userNameTooLong), "whatever", "blah")));
        ////}

        [Fact]
        public async Task AddDupeLoginFailsTest()
        {
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("DupeLogin");
            var login = new UserLoginInfo("provder", "key");
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            UnitTestHelper.IsSuccess(await manager.AddLoginAsync(user.Id, login));
            var result = await manager.AddLoginAsync(user.Id, login);
            UnitTestHelper.IsFailure(result, "A user with that external login already exists.");
        }

        [Fact]
        public async Task AddLoginDoesNotChangeStampTest()
        {
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("stampTest");
            var login = new UserLoginInfo("provder", "key");
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            var stamp = await manager.GetSecurityStampAsync(user.Id);
            UnitTestHelper.IsSuccess(await manager.AddLoginAsync(user.Id, login));
            Assert.Equal(stamp, await manager.GetSecurityStampAsync(user.Id));
        }

        [Fact]
        public async Task MixManagerAndEfTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var manager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            var user = new IdentityUser("MixEFManagerTest");
            var password = "password";
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user, password));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            user.SecurityStamp = "bogus";
            UnitTestHelper.IsSuccess(await manager.UpdateAsync(user));
            Assert.Equal("bogus", db.Users.Find(user.Id).SecurityStamp);
            //var login = new UserLoginInfo("login", "key");
            //user.Logins.Add(new IdentityUserLogin() { User = user, LoginProvider = login.LoginProvider, ProviderKey = login.ProviderKey });
            //UnitTestHelper.IsSuccess(manager.Update(user));
            //Assert.Equal(login.LoginProvider, db.Users.Find(user.Id).Logins.First().LoginProvider);
            //Assert.Equal(login.ProviderKey, db.Users.Find(user.Id).Logins.First().ProviderKey);
        }

        [Fact]
        public async Task CreateUserBasicStoreTest()
        {
            var manager = new UserManager<IdentityUser>(new NoopUserStore());
            UnitTestHelper.IsSuccess(await manager.CreateAsync(new IdentityUser("test")));
        }

        [Fact]
        public async Task GetAllUsersTest()
        {
            var mgr = TestUtil.CreateManager();
            var users = new[]
            {
                new IdentityUser("user1"),
                new IdentityUser("user2"),
                new IdentityUser("user3")
            };
            foreach (IdentityUser u in users)
            {
                UnitTestHelper.IsSuccess(await mgr.CreateAsync(u));
            }
            IQueryable<IUser> usersQ = mgr.Users;
            Assert.Equal(3, usersQ.Count());
            Assert.NotNull(usersQ.Where(u => u.UserName == "user1").FirstOrDefault());
            Assert.NotNull(usersQ.Where(u => u.UserName == "user2").FirstOrDefault());
            Assert.NotNull(usersQ.Where(u => u.UserName == "user3").FirstOrDefault());
            Assert.Null(usersQ.Where(u => u.UserName == "bogus").FirstOrDefault());
        }

        [Fact]
        public async Task ConfirmEmailFalseByDefaultTest()
        {
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("test");
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            Assert.False(await manager.IsEmailConfirmedAsync(user.Id));
        }

        [Fact]
        public async Task ConfirmEmailTest()
        {
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("test");
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
        public void ConfirmEmailSyncTest()
        {
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("test");
            Assert.False(user.EmailConfirmed);
            UnitTestHelper.IsSuccess(manager.Create(user));
            var token = manager.GenerateEmailConfirmationToken(user.Id);
            Assert.NotNull(token);
            UnitTestHelper.IsSuccess(manager.ConfirmEmail(user.Id, token));
            Assert.True(manager.IsEmailConfirmed(user.Id));
            UnitTestHelper.IsSuccess(manager.SetEmail(user.Id, null));
            Assert.False(manager.IsEmailConfirmed(user.Id));
        }

        [Fact]
        public async Task ConfirmTokenFailsAfterPasswordChangeTest()
        {
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("test");
            Assert.False(user.EmailConfirmed);
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user, "password"));
            var token = await manager.GenerateEmailConfirmationTokenAsync(user.Id);
            Assert.NotNull(token);
            UnitTestHelper.IsSuccess(await manager.ChangePasswordAsync(user.Id, "password", "newpassword"));
            UnitTestHelper.IsFailure(await manager.ConfirmEmailAsync(user.Id, token), "Invalid token.");
            Assert.False(await manager.IsEmailConfirmedAsync(user.Id));
        }

        [Fact]
        public async Task FindByEmailTest()
        {
            var manager = TestUtil.CreateManager();
            const string userName = "EmailTest";
            const string email = "email@test.com";
            var user = new IdentityUser(userName) { Email = email };
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            var fetch = await manager.FindByEmailAsync(email);
            Assert.Equal(user, fetch);
        }

        [Fact]
        public void FindByEmailSyncTest()
        {
            var manager = TestUtil.CreateManager();
            var userName = "EmailTest";
            var email = "email@test.com";
            var user = new IdentityUser(userName) { Email = email };
            UnitTestHelper.IsSuccess(manager.Create(user));
            var fetch = manager.FindByEmail(email);
            Assert.Equal(user, fetch);
        }

        [Fact]
        public async Task SetEmailTest()
        {
            var manager = TestUtil.CreateManager();
            var userName = "EmailTest";
            var email = "email@test.com";
            var user = new IdentityUser(userName);
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            Assert.Null(await manager.FindByEmailAsync(email));
            var stamp = await manager.GetSecurityStampAsync(user.Id);
            UnitTestHelper.IsSuccess(await manager.SetEmailAsync(user.Id, email));
            var fetch = await manager.FindByEmailAsync(email);
            Assert.Equal(user, fetch);
            Assert.Equal(email, await manager.GetEmailAsync(user.Id));
            Assert.False(await manager.IsEmailConfirmedAsync(user.Id));
            Assert.NotEqual(stamp, user.SecurityStamp);
        }

        [Fact]
        public async Task CreateDupeEmailFailsTest()
        {
            var manager = TestUtil.CreateManager();
            manager.UserValidator = new UserValidator<IdentityUser>(manager) { RequireUniqueEmail = true };
            var userName = "EmailTest";
            var email = "email@test.com";
            UnitTestHelper.IsSuccess(await manager.CreateAsync(new IdentityUser(userName) { Email = email }));
            var user = new IdentityUser("two") { Email = email };
            UnitTestHelper.IsFailure(await manager.CreateAsync(user), "Email 'email@test.com' is already taken.");
        }

        [Fact]
        public async Task SetEmailToDupeFailsTest()
        {
            var manager = TestUtil.CreateManager();
            manager.UserValidator = new UserValidator<IdentityUser>(manager) { RequireUniqueEmail = true };
            var email = "email@test.com";
            UnitTestHelper.IsSuccess(await manager.CreateAsync(new IdentityUser("emailtest") { Email = email }));
            var user = new IdentityUser("two") { Email = "something@else.com" };
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            UnitTestHelper.IsFailure(await manager.SetEmailAsync(user.Id, email),
                "Email 'email@test.com' is already taken.");
        }

        [Fact]
        public async Task RequireUniqueEmailBlocksBasicCreateTest()
        {
            var manager = TestUtil.CreateManager();
            manager.UserValidator = new UserValidator<IdentityUser>(manager) { RequireUniqueEmail = true };
            UnitTestHelper.IsFailure(await manager.CreateAsync(new IdentityUser("emailtest"), "Email is too short."));
        }

        [Fact]
        public async Task RequireUniqueEmailBlocksInvalidEmailTest()
        {
            var manager = TestUtil.CreateManager();
            manager.UserValidator = new UserValidator<IdentityUser>(manager) { RequireUniqueEmail = true };
            UnitTestHelper.IsFailure(await manager.CreateAsync(new IdentityUser("emailtest") { Email = "hi" }),
                "Email 'hi' is invalid.");
        }

        [Fact]
        public async Task SetPhoneNumberTest()
        {
            var manager = TestUtil.CreateManager();
            var userName = "PhoneTest";
            var user = new IdentityUser(userName);
            user.PhoneNumber = "123-456-7890";
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            var stamp = await manager.GetSecurityStampAsync(user.Id);
            Assert.Equal(await manager.GetPhoneNumberAsync(user.Id), "123-456-7890");
            UnitTestHelper.IsSuccess(await manager.SetPhoneNumberAsync(user.Id, "111-111-1111"));
            Assert.Equal(await manager.GetPhoneNumberAsync(user.Id), "111-111-1111");
            Assert.NotEqual(stamp, user.SecurityStamp);
        }

        [Fact]
        public void SetPhoneNumberSyncTest()
        {
            var manager = TestUtil.CreateManager();
            var userName = "PhoneTest";
            var user = new IdentityUser(userName);
            user.PhoneNumber = "123-456-7890";
            UnitTestHelper.IsSuccess(manager.Create(user));
            var stamp = manager.GetSecurityStamp(user.Id);
            Assert.Equal(manager.GetPhoneNumber(user.Id), "123-456-7890");
            UnitTestHelper.IsSuccess(manager.SetPhoneNumber(user.Id, "111-111-1111"));
            Assert.Equal(manager.GetPhoneNumber(user.Id), "111-111-1111");
            Assert.NotEqual(stamp, user.SecurityStamp);
        }

        [Fact]
        public async Task ChangePhoneNumberTest()
        {
            var manager = TestUtil.CreateManager();
            var userName = "PhoneTest";
            var user = new IdentityUser(userName);
            user.PhoneNumber = "123-456-7890";
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            Assert.False(await manager.IsPhoneNumberConfirmedAsync(user.Id));
            var stamp = await manager.GetSecurityStampAsync(user.Id);
            var token1 = await manager.GenerateChangePhoneNumberTokenAsync(user.Id, "111-111-1111");
            UnitTestHelper.IsSuccess(await manager.ChangePhoneNumberAsync(user.Id, "111-111-1111", token1));
            Assert.True(await manager.IsPhoneNumberConfirmedAsync(user.Id));
            Assert.Equal(await manager.GetPhoneNumberAsync(user.Id), "111-111-1111");
            Assert.NotEqual(stamp, user.SecurityStamp);
        }

        [Fact]
        public void ChangePhoneNumberSyncTest()
        {
            var manager = TestUtil.CreateManager();
            var userName = "PhoneTest";
            var user = new IdentityUser(userName);
            user.PhoneNumber = "123-456-7890";
            UnitTestHelper.IsSuccess(manager.Create(user));
            var stamp = manager.GetSecurityStamp(user.Id);
            Assert.False(manager.IsPhoneNumberConfirmed(user.Id));
            var token1 = manager.GenerateChangePhoneNumberToken(user.Id, "111-111-1111");
            UnitTestHelper.IsSuccess(manager.ChangePhoneNumber(user.Id, "111-111-1111", token1));
            Assert.True(manager.IsPhoneNumberConfirmed(user.Id));
            Assert.Equal(manager.GetPhoneNumber(user.Id), "111-111-1111");
            Assert.NotEqual(stamp, user.SecurityStamp);
        }

        [Fact]
        public async Task ChangePhoneNumberFailsWithWrongTokenTest()
        {
            var manager = TestUtil.CreateManager();
            var userName = "PhoneTest";
            var user = new IdentityUser(userName);
            user.PhoneNumber = "123-456-7890";
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            Assert.False(await manager.IsPhoneNumberConfirmedAsync(user.Id));
            var stamp = await manager.GetSecurityStampAsync(user.Id);
            UnitTestHelper.IsFailure(await manager.ChangePhoneNumberAsync(user.Id, "111-111-1111", "bogus"),
                "Invalid token.");
            Assert.False(await manager.IsPhoneNumberConfirmedAsync(user.Id));
            Assert.Equal(await manager.GetPhoneNumberAsync(user.Id), "123-456-7890");
            Assert.Equal(stamp, user.SecurityStamp);
        }

        [Fact]
        public async Task VerifyPhoneNumberTest()
        {
            var manager = TestUtil.CreateManager();
            var userName = "VerifyPhoneTest";
            var user = new IdentityUser(userName);
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            var num1 = "111-123-4567";
            var num2 = "111-111-1111";
            var token1 = await manager.GenerateChangePhoneNumberTokenAsync(user.Id, num1);
            var token2 = await manager.GenerateChangePhoneNumberTokenAsync(user.Id, num2);
            Assert.NotEqual(token1, token2);
            Assert.True(await manager.VerifyChangePhoneNumberTokenAsync(user.Id, token1, num1));
            Assert.True(await manager.VerifyChangePhoneNumberTokenAsync(user.Id, token2, num2));
            Assert.False(await manager.VerifyChangePhoneNumberTokenAsync(user.Id, token2, num1));
            Assert.False(await manager.VerifyChangePhoneNumberTokenAsync(user.Id, token1, num2));
        }

        [Fact]
        public void VerifyPhoneNumberSyncTest()
        {
            var manager = TestUtil.CreateManager();
            const string userName = "VerifyPhoneTest";
            var user = new IdentityUser(userName);
            UnitTestHelper.IsSuccess(manager.Create(user));
            const string num1 = "111-123-4567";
            const string num2 = "111-111-1111";
            Assert.False(manager.IsPhoneNumberConfirmed(user.Id));
            var token1 = manager.GenerateChangePhoneNumberToken(user.Id, num1);
            var token2 = manager.GenerateChangePhoneNumberToken(user.Id, num2);
            Assert.NotEqual(token1, token2);
            Assert.True(manager.VerifyChangePhoneNumberToken(user.Id, token1, num1));
            Assert.True(manager.VerifyChangePhoneNumberToken(user.Id, token2, num2));
            Assert.False(manager.VerifyChangePhoneNumberToken(user.Id, token2, num1));
            Assert.False(manager.VerifyChangePhoneNumberToken(user.Id, token1, num2));
        }

        [Fact]
        public async Task EmailTokenFactorTest()
        {
            var manager = TestUtil.CreateManager();
            var messageService = new TestMessageService();
            manager.EmailService = messageService;
            const string factorId = "EmailCode";
            manager.RegisterTwoFactorProvider(factorId, new EmailTokenProvider<IdentityUser>());
            var user = new IdentityUser("EmailCodeTest") { Email = "foo@foo.com" };
            const string password = "password";
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user, password));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = await manager.GenerateTwoFactorTokenAsync(user.Id, factorId);
            Assert.NotNull(token);
            Assert.Null(messageService.Message);
            UnitTestHelper.IsSuccess(await manager.NotifyTwoFactorTokenAsync(user.Id, factorId, token));
            Assert.NotNull(messageService.Message);
            Assert.Equal(String.Empty, messageService.Message.Subject);
            Assert.Equal(token, messageService.Message.Body);
            Assert.True(await manager.VerifyTwoFactorTokenAsync(user.Id, factorId, token));
        }

        [Fact]
        public async Task EmailTokenFactorWithFormatTest()
        {
            var manager = TestUtil.CreateManager();
            var messageService = new TestMessageService();
            manager.EmailService = messageService;
            const string factorId = "EmailCode";
            manager.RegisterTwoFactorProvider(factorId, new EmailTokenProvider<IdentityUser>
            {
                Subject = "Security Code",
                BodyFormat = "Your code is: {0}"
            });
            var user = new IdentityUser("EmailCodeTest") { Email = "foo@foo.com" };
            const string password = "password";
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user, password));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = await manager.GenerateTwoFactorTokenAsync(user.Id, factorId);
            Assert.NotNull(token);
            Assert.Null(messageService.Message);
            UnitTestHelper.IsSuccess(await manager.NotifyTwoFactorTokenAsync(user.Id, factorId, token));
            Assert.NotNull(messageService.Message);
            Assert.Equal("Security Code", messageService.Message.Subject);
            Assert.Equal("Your code is: " + token, messageService.Message.Body);
            Assert.True(await manager.VerifyTwoFactorTokenAsync(user.Id, factorId, token));
        }

        [Fact]
        public void EmailTokenFactorWithFormatSyncTest()
        {
            var manager = TestUtil.CreateManager();
            var messageService = new TestMessageService();
            manager.EmailService = messageService;
            const string factorId = "EmailCode";
            manager.RegisterTwoFactorProvider(factorId, new EmailTokenProvider<IdentityUser>
            {
                Subject = "Security Code",
                BodyFormat = "Your code is: {0}"
            });
            var user = new IdentityUser("EmailCodeTest") { Email = "foo@foo.com" };
            const string password = "password";
            UnitTestHelper.IsSuccess(manager.Create(user, password));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = manager.GenerateTwoFactorToken(user.Id, factorId);
            Assert.NotNull(token);
            Assert.Null(messageService.Message);
            UnitTestHelper.IsSuccess(manager.NotifyTwoFactorToken(user.Id, factorId, token));
            Assert.NotNull(messageService.Message);
            Assert.Equal("Security Code", messageService.Message.Subject);
            Assert.Equal("Your code is: " + token, messageService.Message.Body);
            Assert.True(manager.VerifyTwoFactorToken(user.Id, factorId, token));
        }

        [Fact]
        public async Task EmailFactorFailsAfterSecurityStampChangeTest()
        {
            var manager = TestUtil.CreateManager();
            const string factorId = "EmailCode";
            manager.RegisterTwoFactorProvider(factorId, new EmailTokenProvider<IdentityUser>());
            var user = new IdentityUser("EmailCodeTest") { Email = "foo@foo.com" };
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = await manager.GenerateTwoFactorTokenAsync(user.Id, factorId);
            Assert.NotNull(token);
            UnitTestHelper.IsSuccess(await manager.UpdateSecurityStampAsync(user.Id));
            Assert.False(await manager.VerifyTwoFactorTokenAsync(user.Id, factorId, token));
        }

        [Fact]
        public void EmailTokenFactorSyncTest()
        {
            var manager = TestUtil.CreateManager();
            const string factorId = "EmailCode";
            manager.RegisterTwoFactorProvider(factorId, new EmailTokenProvider<IdentityUser>());
            var user = new IdentityUser("EmailCodeTest") { Email = "foo@foo.com" };
            const string password = "password";
            UnitTestHelper.IsSuccess(manager.Create(user, password));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = manager.GenerateTwoFactorToken(user.Id, factorId);
            Assert.NotNull(token);
            Assert.True(manager.VerifyTwoFactorToken(user.Id, factorId, token));
        }

        [Fact]
        public void EmailFactorFailsAfterSecurityStampChangeSyncTest()
        {
            var manager = TestUtil.CreateManager();
            const string factorId = "EmailCode";
            manager.RegisterTwoFactorProvider(factorId, new EmailTokenProvider<IdentityUser>());
            var user = new IdentityUser("EmailCodeTest") { Email = "foo@foo.com" };
            UnitTestHelper.IsSuccess(manager.Create(user));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = manager.GenerateTwoFactorToken(user.Id, factorId);
            Assert.NotNull(token);
            UnitTestHelper.IsSuccess(manager.UpdateSecurityStamp(user.Id));
            Assert.False(manager.VerifyTwoFactorToken(user.Id, factorId, token));
        }

        [Fact]
        public async Task UserTwoFactorProviderTest()
        {
            var manager = TestUtil.CreateManager();
            const string factorId = "PhoneCode";
            manager.RegisterTwoFactorProvider(factorId, new PhoneNumberTokenProvider<IdentityUser>());
            var user = new IdentityUser("PhoneCodeTest");
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            UnitTestHelper.IsSuccess(await manager.SetTwoFactorEnabledAsync(user.Id, true));
            Assert.NotEqual(stamp, await manager.GetSecurityStampAsync(user.Id));
            Assert.True(await manager.GetTwoFactorEnabledAsync(user.Id));
        }

        [Fact]
        public async Task SendSms()
        {
            var manager = TestUtil.CreateManager();
            var messageService = new TestMessageService();
            manager.SmsService = messageService;
            var user = new IdentityUser("SmsTest") { PhoneNumber = "4251234567" };
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            await manager.SendSmsAsync(user.Id, "Hi");
            Assert.NotNull(messageService.Message);
            Assert.Equal("Hi", messageService.Message.Body);
        }

        [Fact]
        public async Task SendEmail()
        {
            var manager = TestUtil.CreateManager();
            var messageService = new TestMessageService();
            manager.EmailService = messageService;
            var user = new IdentityUser("EmailTest") { Email = "foo@foo.com" };
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            await manager.SendEmailAsync(user.Id, "Hi", "Body");
            Assert.NotNull(messageService.Message);
            Assert.Equal("Hi", messageService.Message.Subject);
            Assert.Equal("Body", messageService.Message.Body);
        }

        [Fact]
        public void SendSmsSync()
        {
            var manager = TestUtil.CreateManager();
            var messageService = new TestMessageService();
            manager.SmsService = messageService;
            var user = new IdentityUser("SmsTest") { PhoneNumber = "4251234567" };
            UnitTestHelper.IsSuccess(manager.Create(user));
            manager.SendSms(user.Id, "Hi");
            Assert.NotNull(messageService.Message);
            Assert.Equal("Hi", messageService.Message.Body);
        }

        [Fact]
        public void SendEmailSync()
        {
            var manager = TestUtil.CreateManager();
            var messageService = new TestMessageService();
            manager.EmailService = messageService;
            var user = new IdentityUser("EmailTest") { Email = "foo@foo.com" };
            UnitTestHelper.IsSuccess(manager.Create(user));
            manager.SendEmail(user.Id, "Hi", "Body");
            Assert.NotNull(messageService.Message);
            Assert.Equal("Hi", messageService.Message.Subject);
            Assert.Equal("Body", messageService.Message.Body);
        }


        [Fact]
        public async Task PhoneTokenFactorTest()
        {
            var manager = TestUtil.CreateManager();
            var messageService = new TestMessageService();
            manager.SmsService = messageService;
            const string factorId = "PhoneCode";
            manager.RegisterTwoFactorProvider(factorId, new PhoneNumberTokenProvider<IdentityUser>());
            var user = new IdentityUser("PhoneCodeTest") { PhoneNumber = "4251234567" };
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = await manager.GenerateTwoFactorTokenAsync(user.Id, factorId);
            Assert.NotNull(token);
            Assert.Null(messageService.Message);
            UnitTestHelper.IsSuccess(await manager.NotifyTwoFactorTokenAsync(user.Id, factorId, token));
            Assert.NotNull(messageService.Message);
            Assert.Equal(token, messageService.Message.Body);
            Assert.True(await manager.VerifyTwoFactorTokenAsync(user.Id, factorId, token));
        }

        [Fact]
        public void PhoneTokenFactorSyncTest()
        {
            var manager = TestUtil.CreateManager();
            var messageService = new TestMessageService();
            manager.SmsService = messageService;
            const string factorId = "PhoneCode";
            manager.RegisterTwoFactorProvider(factorId, new PhoneNumberTokenProvider<IdentityUser>());
            var user = new IdentityUser("PhoneCodeTest") { PhoneNumber = "4251234567" };
            UnitTestHelper.IsSuccess(manager.Create(user));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = manager.GenerateTwoFactorToken(user.Id, factorId);
            Assert.NotNull(token);
            Assert.Null(messageService.Message);
            UnitTestHelper.IsSuccess(manager.NotifyTwoFactorToken(user.Id, factorId, token));
            Assert.NotNull(messageService.Message);
            Assert.Equal(token, messageService.Message.Body);
            Assert.True(manager.VerifyTwoFactorToken(user.Id, factorId, token));
        }

        [Fact]
        public async Task PhoneTokenFactorFormatTest()
        {
            var manager = TestUtil.CreateManager();
            var messageService = new TestMessageService();
            manager.SmsService = messageService;
            const string factorId = "PhoneCode";
            manager.RegisterTwoFactorProvider(factorId, new PhoneNumberTokenProvider<IdentityUser>
            {
                MessageFormat = "Your code is: {0}"
            });
            var user = new IdentityUser("PhoneCodeTest") { PhoneNumber = "4251234567" };
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = await manager.GenerateTwoFactorTokenAsync(user.Id, factorId);
            Assert.NotNull(token);
            Assert.Null(messageService.Message);
            UnitTestHelper.IsSuccess(await manager.NotifyTwoFactorTokenAsync(user.Id, factorId, token));
            Assert.NotNull(messageService.Message);
            Assert.Equal("Your code is: " + token, messageService.Message.Body);
            Assert.True(await manager.VerifyTwoFactorTokenAsync(user.Id, factorId, token));
        }

        [Fact]
        public async Task NoFactorProviderTest()
        {
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("PhoneCodeTest");
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            const string error = "No IUserTwoFactorProvider for 'bogus' is registered.";
            ExceptionHelper.ThrowsWithError<NotSupportedException>(
                () => manager.GenerateTwoFactorToken(user.Id, "bogus"), error);
            ExceptionHelper.ThrowsWithError<NotSupportedException>(
                () => manager.VerifyTwoFactorToken(user.Id, "bogus", "bogus"), error);
        }

        [Fact]
        public async Task GetValidTwoFactorTestEmptyWithNoProviders()
        {
            var manager = TestUtil.CreateManager();
            var user = new IdentityUser("test");
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            var factors = await manager.GetValidTwoFactorProvidersAsync(user.Id);
            Assert.NotNull(factors);
            Assert.True(!factors.Any());
        }

        [Fact]
        public async Task GetValidTwoFactorTest()
        {
            var manager = TestUtil.CreateManager();
            manager.RegisterTwoFactorProvider("phone", new PhoneNumberTokenProvider<IdentityUser>());
            manager.RegisterTwoFactorProvider("email", new EmailTokenProvider<IdentityUser>());
            var user = new IdentityUser("test");
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            var factors = await manager.GetValidTwoFactorProvidersAsync(user.Id);
            Assert.NotNull(factors);
            UnitTestHelper.IsSuccess(await manager.SetPhoneNumberAsync(user.Id, "111-111-1111"));
            factors = await manager.GetValidTwoFactorProvidersAsync(user.Id);
            Assert.False(factors.Any());
            // Need to confirm
            user.PhoneNumberConfirmed = true;
            UnitTestHelper.IsSuccess(manager.Update(user));
            factors = await manager.GetValidTwoFactorProvidersAsync(user.Id);
            Assert.True(factors.Count() == 1);
            Assert.Equal("phone", factors[0]);
            Assert.NotNull(factors);
            Assert.True(factors.Count() == 1);
            Assert.Equal("phone", factors[0]);
            UnitTestHelper.IsSuccess(await manager.SetEmailAsync(user.Id, "test@test.com"));
            factors = await manager.GetValidTwoFactorProvidersAsync(user.Id);
            Assert.NotNull(factors);
            Assert.True(factors.Count() == 1);
            // Need to confirm
            user.EmailConfirmed = true;
            UnitTestHelper.IsSuccess(await manager.UpdateAsync(user));
            factors = await manager.GetValidTwoFactorProvidersAsync(user.Id);
            Assert.NotNull(factors);
            Assert.True(factors.Count() == 2);
            UnitTestHelper.IsSuccess(await manager.SetEmailAsync(user.Id, "somethingelse"));
            factors = await manager.GetValidTwoFactorProvidersAsync(user.Id);
            Assert.NotNull(factors);
            Assert.True(factors.Count() == 1);
            Assert.Equal("phone", factors[0]);
        }

        [Fact]
        public void GetValidTwoFactorSyncTest()
        {
            var manager = TestUtil.CreateManager();
            manager.RegisterTwoFactorProvider("phone", new PhoneNumberTokenProvider<IdentityUser>());
            manager.RegisterTwoFactorProvider("email", new EmailTokenProvider<IdentityUser>());
            var user = new IdentityUser("test");
            UnitTestHelper.IsSuccess(manager.Create(user));
            var factors = manager.GetValidTwoFactorProviders(user.Id);
            Assert.NotNull(factors);
            Assert.False(factors.Any());
            UnitTestHelper.IsSuccess(manager.SetPhoneNumber(user.Id, "111-111-1111"));
            factors = manager.GetValidTwoFactorProviders(user.Id);
            Assert.NotNull(factors);
            Assert.False(factors.Any());
            // Need to confirm
            user.PhoneNumberConfirmed = true;
            UnitTestHelper.IsSuccess(manager.Update(user));
            factors = manager.GetValidTwoFactorProviders(user.Id);
            Assert.True(factors.Count() == 1);
            Assert.Equal("phone", factors[0]);
            UnitTestHelper.IsSuccess(manager.SetEmail(user.Id, "test@test.com"));
            factors = manager.GetValidTwoFactorProviders(user.Id);
            Assert.NotNull(factors);
            Assert.True(factors.Count() == 1);
            // Need to confirm
            user.EmailConfirmed = true;
            UnitTestHelper.IsSuccess(manager.Update(user));
            factors = manager.GetValidTwoFactorProviders(user.Id);
            Assert.NotNull(factors);
            Assert.True(factors.Count() == 2);
            UnitTestHelper.IsSuccess(manager.SetEmail(user.Id, null));
            factors = manager.GetValidTwoFactorProviders(user.Id);
            Assert.NotNull(factors);
            Assert.True(factors.Count() == 1);
            Assert.Equal("phone", factors[0]);
        }

        [Fact]
        public async Task PhoneFactorFailsAfterSecurityStampChangeTest()
        {
            var manager = TestUtil.CreateManager();
            var factorId = "PhoneCode";
            manager.RegisterTwoFactorProvider(factorId, new PhoneNumberTokenProvider<IdentityUser>());
            var user = new IdentityUser("PhoneCodeTest");
            user.PhoneNumber = "4251234567";
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = await manager.GenerateTwoFactorTokenAsync(user.Id, factorId);
            Assert.NotNull(token);
            UnitTestHelper.IsSuccess(await manager.UpdateSecurityStampAsync(user.Id));
            Assert.False(await manager.VerifyTwoFactorTokenAsync(user.Id, factorId, token));
        }

        [Fact]
        public async Task WrongTokenProviderFailsTest()
        {
            var manager = TestUtil.CreateManager();
            var factorId = "PhoneCode";
            manager.RegisterTwoFactorProvider(factorId, new PhoneNumberTokenProvider<IdentityUser>());
            manager.RegisterTwoFactorProvider("EmailCode", new EmailTokenProvider<IdentityUser>());
            var user = new IdentityUser("PhoneCodeTest");
            user.PhoneNumber = "4251234567";
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = await manager.GenerateTwoFactorTokenAsync(user.Id, factorId);
            Assert.NotNull(token);
            Assert.False(await manager.VerifyTwoFactorTokenAsync(user.Id, "EmailCode", token));
        }

        [Fact]
        public async Task WrongTokenFailsTest()
        {
            var manager = TestUtil.CreateManager();
            var factorId = "PhoneCode";
            manager.RegisterTwoFactorProvider(factorId, new PhoneNumberTokenProvider<IdentityUser>());
            var user = new IdentityUser("PhoneCodeTest");
            user.PhoneNumber = "4251234567";
            UnitTestHelper.IsSuccess(await manager.CreateAsync(user));
            var stamp = user.SecurityStamp;
            Assert.NotNull(stamp);
            var token = await manager.GenerateTwoFactorTokenAsync(user.Id, factorId);
            Assert.NotNull(token);
            Assert.False(await manager.VerifyTwoFactorTokenAsync(user.Id, factorId, "abc"));
        }

        [Fact]
        public async Task ResetTokenCallNoopForTokenValueZero()
        {
            var user = new IdentityUser() { UserName = "foo" };
            var store = new Mock<UserStore<IdentityUser>>();
            store.Setup(x => x.ResetAccessFailedCountAsync(user)).Returns(() =>
             {
                 throw new Exception();
             });
            store.Setup(x => x.FindByIdAsync(It.IsAny<string>()))
                .Returns(() => Task.FromResult(user));
            store.Setup(x => x.GetAccessFailedCountAsync(It.IsAny<IdentityUser>()))
                .Returns(() => Task.FromResult(0));
            var manager = new UserManager<IdentityUser>(store.Object);
            UnitTestHelper.IsSuccess(await manager.ResetAccessFailedCountAsync(user.Id));
        }

        [Fact]
        public void Create_preserves_culture()
        {
            var originalCulture = Thread.CurrentThread.CurrentCulture;
            var originalUICulture = Thread.CurrentThread.CurrentUICulture;
            var expectedCulture = new CultureInfo("de-DE");
            Thread.CurrentThread.CurrentCulture = expectedCulture;
            Thread.CurrentThread.CurrentUICulture = expectedCulture;
            var manager = TestUtil.CreateManager();

            try
            {
                var cultures = GetCurrentCultureAfter(() => manager.CreateAsync(new IdentityUser("whatever"))).Result;
                Assert.Equal(expectedCulture, cultures.Item1);
                Assert.Equal(expectedCulture, cultures.Item2);
            }
            finally
            {
                Thread.CurrentThread.CurrentCulture = originalCulture;
                Thread.CurrentThread.CurrentUICulture = originalUICulture;
            }
        }

        [Fact]
        public void CreateSync_preserves_culture()
        {
            var originalCulture = Thread.CurrentThread.CurrentCulture;
            var originalUICulture = Thread.CurrentThread.CurrentUICulture;
            var expectedCulture = new CultureInfo("de-DE");
            Thread.CurrentThread.CurrentCulture = expectedCulture;
            Thread.CurrentThread.CurrentUICulture = expectedCulture;
            var manager = TestUtil.CreateManager();

            try
            {
                var cultures = GetCurrentCultureAfter(() => manager.Create(new IdentityUser("whatever")));
                Assert.Equal(expectedCulture, cultures.Item1);
                Assert.Equal(expectedCulture, cultures.Item2);
            }
            finally
            {
                Thread.CurrentThread.CurrentCulture = originalCulture;
                Thread.CurrentThread.CurrentUICulture = originalUICulture;
            }
        }

        private static async Task<Tuple<CultureInfo, CultureInfo>> GetCurrentCultureAfter(Func<Task> action)
        {
            await action();
            return new Tuple<CultureInfo, CultureInfo>(Thread.CurrentThread.CurrentCulture, Thread.CurrentThread.CurrentUICulture);
        }

        private static Tuple<CultureInfo, CultureInfo> GetCurrentCultureAfter(Action action)
        {
            action();
            return new Tuple<CultureInfo, CultureInfo>(Thread.CurrentThread.CurrentCulture, Thread.CurrentThread.CurrentUICulture);
        }

        private class NoOpTokenProvider : IUserTokenProvider<IdentityUser, string>
        {
            public Task<string> GenerateAsync(string purpose, UserManager<IdentityUser, string> manager,
                IdentityUser user)
            {
                throw new NotImplementedException();
            }

            public Task<bool> ValidateAsync(string purpose, string token, UserManager<IdentityUser, string> manager,
                IdentityUser user)
            {
                throw new NotImplementedException();
            }

            public Task NotifyAsync(string token, UserManager<IdentityUser, string> manager, IdentityUser user)
            {
                throw new NotImplementedException();
            }

            public Task<bool> IsValidProviderForUserAsync(UserManager<IdentityUser, string> manager, IdentityUser user)
            {
                throw new NotImplementedException();
            }
        }

        private class NoStampUserManager : UserManager<IdentityUser>
        {
            public NoStampUserManager()
                : base(new UserStore<IdentityUser>(UnitTestHelper.CreateDefaultDb()))
            {
                UserValidator = new UserValidator<IdentityUser>(this)
                {
                    AllowOnlyAlphanumericUserNames = true,
                    RequireUniqueEmail = false
                };
                var dpp = new DpapiDataProtectionProvider();
                UserTokenProvider = new DataProtectorTokenProvider<IdentityUser>(dpp.Create("ASP.NET Identity"));
            }

            public override bool SupportsUserSecurityStamp
            {
                get { return false; }
            }
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