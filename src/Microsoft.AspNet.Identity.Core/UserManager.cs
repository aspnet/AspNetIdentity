// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.AspNet.Identity
{
    /// <summary>
    ///     UserManager for users where the primary key for the User is of type string
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    public class UserManager<TUser> : UserManager<TUser, string> where TUser : class, IUser<string>
    {
        /// <summary>
        ///     Constructor
        /// </summary>
        /// <param name="store"></param>
        public UserManager(IUserStore<TUser> store)
            : base(store)
        {
        }
    }

    /// <summary>
    ///     Exposes user related api which will automatically save changes to the UserStore
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    /// <typeparam name="TKey"></typeparam>
    public class UserManager<TUser, TKey> : IDisposable
        where TUser : class, IUser<TKey>
        where TKey : IEquatable<TKey>
    {
        private readonly Dictionary<string, IUserTokenProvider<TUser, TKey>> _factors =
            new Dictionary<string, IUserTokenProvider<TUser, TKey>>();

        private IClaimsIdentityFactory<TUser, TKey> _claimsFactory;
        private TimeSpan _defaultLockout = TimeSpan.Zero;
        private bool _disposed;
        private IPasswordHasher _passwordHasher;
        private IIdentityValidator<string> _passwordValidator;
        private IIdentityValidator<TUser> _userValidator;

        /// <summary>
        ///     Constructor
        /// </summary>
        /// <param name="store">The IUserStore is responsible for commiting changes via the UpdateAsync/CreateAsync methods</param>
        public UserManager(IUserStore<TUser, TKey> store)
        {
            if (store == null)
            {
                throw new ArgumentNullException("store");
            }
            Store = store;
            UserValidator = new UserValidator<TUser, TKey>(this);
            PasswordValidator = new MinimumLengthValidator(6);
            PasswordHasher = new PasswordHasher();
            ClaimsIdentityFactory = new ClaimsIdentityFactory<TUser, TKey>();
        }

        /// <summary>
        ///     Persistence abstraction that the UserManager operates against
        /// </summary>
        protected internal IUserStore<TUser, TKey> Store { get; set; }

        /// <summary>
        ///     Used to hash/verify passwords
        /// </summary>
        public IPasswordHasher PasswordHasher
        {
            get
            {
                ThrowIfDisposed();
                return _passwordHasher;
            }
            set
            {
                ThrowIfDisposed();
                if (value == null)
                {
                    throw new ArgumentNullException("value");
                }
                _passwordHasher = value;
            }
        }

        /// <summary>
        ///     Used to validate users before changes are saved
        /// </summary>
        public IIdentityValidator<TUser> UserValidator
        {
            get
            {
                ThrowIfDisposed();
                return _userValidator;
            }
            set
            {
                ThrowIfDisposed();
                if (value == null)
                {
                    throw new ArgumentNullException("value");
                }
                _userValidator = value;
            }
        }

        /// <summary>
        ///     Used to validate passwords before persisting changes
        /// </summary>
        public IIdentityValidator<string> PasswordValidator
        {
            get
            {
                ThrowIfDisposed();
                return _passwordValidator;
            }
            set
            {
                ThrowIfDisposed();
                if (value == null)
                {
                    throw new ArgumentNullException("value");
                }
                _passwordValidator = value;
            }
        }

        /// <summary>
        ///     Used to create claims identities from users
        /// </summary>
        public IClaimsIdentityFactory<TUser, TKey> ClaimsIdentityFactory
        {
            get
            {
                ThrowIfDisposed();
                return _claimsFactory;
            }
            set
            {
                ThrowIfDisposed();
                if (value == null)
                {
                    throw new ArgumentNullException("value");
                }
                _claimsFactory = value;
            }
        }

        /// <summary>
        ///     Used to send email
        /// </summary>
        public IIdentityMessageService EmailService { get; set; }

        /// <summary>
        ///     Used to send a sms message
        /// </summary>
        public IIdentityMessageService SmsService { get; set; }

        /// <summary>
        ///     Used for generating reset password and confirmation tokens
        /// </summary>
        public IUserTokenProvider<TUser, TKey> UserTokenProvider { get; set; }

        /// <summary>
        ///     If true, will enable user lockout when users are created
        /// </summary>
        public bool UserLockoutEnabledByDefault { get; set; }

        /// <summary>
        ///     Number of access attempts allowed before a user is locked out (if lockout is enabled)
        /// </summary>
        public int MaxFailedAccessAttemptsBeforeLockout { get; set; }

        /// <summary>
        ///     Default amount of time that a user is locked out for after MaxFailedAccessAttemptsBeforeLockout is reached
        /// </summary>
        public TimeSpan DefaultAccountLockoutTimeSpan
        {
            get { return _defaultLockout; }
            set { _defaultLockout = value; }
        }

        /// <summary>
        ///     Returns true if the store is an IUserTwoFactorStore
        /// </summary>
        public virtual bool SupportsUserTwoFactor
        {
            get
            {
                ThrowIfDisposed();
                return Store is IUserTwoFactorStore<TUser, TKey>;
            }
        }

        /// <summary>
        ///     Returns true if the store is an IUserPasswordStore
        /// </summary>
        public virtual bool SupportsUserPassword
        {
            get
            {
                ThrowIfDisposed();
                return Store is IUserPasswordStore<TUser, TKey>;
            }
        }

        /// <summary>
        ///     Returns true if the store is an IUserSecurityStore
        /// </summary>
        public virtual bool SupportsUserSecurityStamp
        {
            get
            {
                ThrowIfDisposed();
                return Store is IUserSecurityStampStore<TUser, TKey>;
            }
        }

        /// <summary>
        ///     Returns true if the store is an IUserRoleStore
        /// </summary>
        public virtual bool SupportsUserRole
        {
            get
            {
                ThrowIfDisposed();
                return Store is IUserRoleStore<TUser, TKey>;
            }
        }

        /// <summary>
        ///     Returns true if the store is an IUserLoginStore
        /// </summary>
        public virtual bool SupportsUserLogin
        {
            get
            {
                ThrowIfDisposed();
                return Store is IUserLoginStore<TUser, TKey>;
            }
        }

        /// <summary>
        ///     Returns true if the store is an IUserEmailStore
        /// </summary>
        public virtual bool SupportsUserEmail
        {
            get
            {
                ThrowIfDisposed();
                return Store is IUserEmailStore<TUser, TKey>;
            }
        }

        /// <summary>
        ///     Returns true if the store is an IUserPhoneNumberStore
        /// </summary>
        public virtual bool SupportsUserPhoneNumber
        {
            get
            {
                ThrowIfDisposed();
                return Store is IUserPhoneNumberStore<TUser, TKey>;
            }
        }

        /// <summary>
        ///     Returns true if the store is an IUserClaimStore
        /// </summary>
        public virtual bool SupportsUserClaim
        {
            get
            {
                ThrowIfDisposed();
                return Store is IUserClaimStore<TUser, TKey>;
            }
        }

        /// <summary>
        ///     Returns true if the store is an IUserLockoutStore
        /// </summary>
        public virtual bool SupportsUserLockout
        {
            get
            {
                ThrowIfDisposed();
                return Store is IUserLockoutStore<TUser, TKey>;
            }
        }

        /// <summary>
        ///     Returns true if the store is an IQueryableUserStore
        /// </summary>
        public virtual bool SupportsQueryableUsers
        {
            get
            {
                ThrowIfDisposed();
                return Store is IQueryableUserStore<TUser, TKey>;
            }
        }

        /// <summary>
        ///     Returns an IQueryable of users if the store is an IQueryableUserStore
        /// </summary>
        public virtual IQueryable<TUser> Users
        {
            get
            {
                var queryableStore = Store as IQueryableUserStore<TUser, TKey>;
                if (queryableStore == null)
                {
                    throw new NotSupportedException(Resources.StoreNotIQueryableUserStore);
                }
                return queryableStore.Users;
            }
        }

        /// <summary>
        /// Maps the registered two-factor authentication providers for users by their id
        /// </summary>
        public IDictionary<string, IUserTokenProvider<TUser, TKey>> TwoFactorProviders
        {
            get { return _factors; }
        }

        /// <summary>
        ///     Dispose this object
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        ///     Creates a ClaimsIdentity representing the user
        /// </summary>
        /// <param name="user"></param>
        /// <param name="authenticationType"></param>
        /// <returns></returns>
        public virtual Task<ClaimsIdentity> CreateIdentityAsync(TUser user, string authenticationType)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return ClaimsIdentityFactory.CreateAsync(this, user, authenticationType);
        }

        /// <summary>
        ///     Create a user with no password
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> CreateAsync(TUser user)
        {
            ThrowIfDisposed();
            await UpdateSecurityStampInternal(user).WithCurrentCulture();
            var result = await UserValidator.ValidateAsync(user).WithCurrentCulture();
            if (!result.Succeeded)
            {
                return result;
            }
            if (UserLockoutEnabledByDefault && SupportsUserLockout)
            {
                await GetUserLockoutStore().SetLockoutEnabledAsync(user, true).WithCurrentCulture();
            }
            await Store.CreateAsync(user).WithCurrentCulture();
            return IdentityResult.Success;
        }

        /// <summary>
        ///     Update a user
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> UpdateAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var result = await UserValidator.ValidateAsync(user).WithCurrentCulture();
            if (!result.Succeeded)
            {
                return result;
            }
            await Store.UpdateAsync(user).WithCurrentCulture();
            return IdentityResult.Success;
        }

        /// <summary>
        ///     Delete a user
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> DeleteAsync(TUser user)
        {
            ThrowIfDisposed();
            await Store.DeleteAsync(user).WithCurrentCulture();
            return IdentityResult.Success;
        }

        /// <summary>
        ///     Find a user by id
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public virtual Task<TUser> FindByIdAsync(TKey userId)
        {
            ThrowIfDisposed();
            return Store.FindByIdAsync(userId);
        }

        /// <summary>
        ///     Find a user by user name
        /// </summary>
        /// <param name="userName"></param>
        /// <returns></returns>
        public virtual Task<TUser> FindByNameAsync(string userName)
        {
            ThrowIfDisposed();
            if (userName == null)
            {
                throw new ArgumentNullException("userName");
            }
            return Store.FindByNameAsync(userName);
        }

        // IUserPasswordStore methods
        private IUserPasswordStore<TUser, TKey> GetPasswordStore()
        {
            var cast = Store as IUserPasswordStore<TUser, TKey>;
            if (cast == null)
            {
                throw new NotSupportedException(Resources.StoreNotIUserPasswordStore);
            }
            return cast;
        }

        /// <summary>
        ///     Create a user with the given password
        /// </summary>
        /// <param name="user"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> CreateAsync(TUser user, string password)
        {
            ThrowIfDisposed();
            var passwordStore = GetPasswordStore();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (password == null)
            {
                throw new ArgumentNullException("password");
            }
            var result = await UpdatePassword(passwordStore, user, password).WithCurrentCulture();
            if (!result.Succeeded)
            {
                return result;
            }
            return await CreateAsync(user).WithCurrentCulture();
        }

        /// <summary>
        ///     Return a user with the specified username and password or null if there is no match.
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public virtual async Task<TUser> FindAsync(string userName, string password)
        {
            ThrowIfDisposed();
            var user = await FindByNameAsync(userName).WithCurrentCulture();
            if (user == null)
            {
                return null;
            }
            return await CheckPasswordAsync(user, password).WithCurrentCulture() ? user : null;
        }

        /// <summary>
        ///     Returns true if the password is valid for the user
        /// </summary>
        /// <param name="user"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public virtual async Task<bool> CheckPasswordAsync(TUser user, string password)
        {
            ThrowIfDisposed();
            var passwordStore = GetPasswordStore();
            if (user == null)
            {
                return false;
            }
            return await VerifyPasswordAsync(passwordStore, user, password).WithCurrentCulture();
        }

        /// <summary>
        ///     Returns true if the user has a password
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public virtual async Task<bool> HasPasswordAsync(TKey userId)
        {
            ThrowIfDisposed();
            var passwordStore = GetPasswordStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            return await passwordStore.HasPasswordAsync(user).WithCurrentCulture();
        }

        /// <summary>
        ///     Add a user password only if one does not already exist
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> AddPasswordAsync(TKey userId, string password)
        {
            ThrowIfDisposed();
            var passwordStore = GetPasswordStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            var hash = await passwordStore.GetPasswordHashAsync(user).WithCurrentCulture();
            if (hash != null)
            {
                return new IdentityResult(Resources.UserAlreadyHasPassword);
            }
            var result = await UpdatePassword(passwordStore, user, password).WithCurrentCulture();
            if (!result.Succeeded)
            {
                return result;
            }
            return await UpdateAsync(user).WithCurrentCulture();
        }

        /// <summary>
        ///     Change a user password
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="currentPassword"></param>
        /// <param name="newPassword"></param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> ChangePasswordAsync(TKey userId, string currentPassword,
            string newPassword)
        {
            ThrowIfDisposed();
            var passwordStore = GetPasswordStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            if (await VerifyPasswordAsync(passwordStore, user, currentPassword).WithCurrentCulture())
            {
                var result = await UpdatePassword(passwordStore, user, newPassword).WithCurrentCulture();
                if (!result.Succeeded)
                {
                    return result;
                }
                return await UpdateAsync(user).WithCurrentCulture();
            }
            return IdentityResult.Failed(Resources.PasswordMismatch);
        }

        /// <summary>
        ///     Remove a user's password
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> RemovePasswordAsync(TKey userId)
        {
            ThrowIfDisposed();
            var passwordStore = GetPasswordStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            await passwordStore.SetPasswordHashAsync(user, null).WithCurrentCulture();
            await UpdateSecurityStampInternal(user).WithCurrentCulture();
            return await UpdateAsync(user).WithCurrentCulture();
        }

        protected virtual async Task<IdentityResult> UpdatePassword(IUserPasswordStore<TUser, TKey> passwordStore,
            TUser user, string newPassword)
        {
            var result = await PasswordValidator.ValidateAsync(newPassword).WithCurrentCulture();
            if (!result.Succeeded)
            {
                return result;
            }
            await
                passwordStore.SetPasswordHashAsync(user, PasswordHasher.HashPassword(newPassword)).WithCurrentCulture();
            await UpdateSecurityStampInternal(user).WithCurrentCulture();
            return IdentityResult.Success;
        }

        /// <summary>
        ///     By default, retrieves the hashed password from the user store and calls PasswordHasher.VerifyHashPassword
        /// </summary>
        /// <param name="store"></param>
        /// <param name="user"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        protected virtual async Task<bool> VerifyPasswordAsync(IUserPasswordStore<TUser, TKey> store, TUser user,
            string password)
        {
            var hash = await store.GetPasswordHashAsync(user).WithCurrentCulture();
            return PasswordHasher.VerifyHashedPassword(hash, password) != PasswordVerificationResult.Failed;
        }

        // IUserSecurityStampStore methods
        private IUserSecurityStampStore<TUser, TKey> GetSecurityStore()
        {
            var cast = Store as IUserSecurityStampStore<TUser, TKey>;
            if (cast == null)
            {
                throw new NotSupportedException(Resources.StoreNotIUserSecurityStampStore);
            }
            return cast;
        }

        /// <summary>
        ///     Returns the current security stamp for a user
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public virtual async Task<string> GetSecurityStampAsync(TKey userId)
        {
            ThrowIfDisposed();
            var securityStore = GetSecurityStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            return await securityStore.GetSecurityStampAsync(user).WithCurrentCulture();
        }

        /// <summary>
        ///     Generate a new security stamp for a user, used for SignOutEverywhere functionality
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> UpdateSecurityStampAsync(TKey userId)
        {
            ThrowIfDisposed();
            var securityStore = GetSecurityStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            await securityStore.SetSecurityStampAsync(user, NewSecurityStamp()).WithCurrentCulture();
            return await UpdateAsync(user).WithCurrentCulture();
        }

        /// <summary>
        ///     Generate a password reset token for the user using the UserTokenProvider
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public virtual Task<string> GeneratePasswordResetTokenAsync(TKey userId)
        {
            ThrowIfDisposed();
            return GenerateUserTokenAsync("ResetPassword", userId);
        }

        /// <summary>
        ///     Reset a user's password using a reset password token
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="token"></param>
        /// <param name="newPassword"></param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> ResetPasswordAsync(TKey userId, string token, string newPassword)
        {
            ThrowIfDisposed();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            // Make sure the token is valid and the stamp matches
            if (!await VerifyUserTokenAsync(userId, "ResetPassword", token).WithCurrentCulture())
            {
                return IdentityResult.Failed(Resources.InvalidToken);
            }
            var passwordStore = GetPasswordStore();
            var result = await UpdatePassword(passwordStore, user, newPassword).WithCurrentCulture();
            if (!result.Succeeded)
            {
                return result;
            }
            return await UpdateAsync(user).WithCurrentCulture();
        }

        // Update the security stamp if the store supports it
        internal async Task UpdateSecurityStampInternal(TUser user)
        {
            if (SupportsUserSecurityStamp)
            {
                await GetSecurityStore().SetSecurityStampAsync(user, NewSecurityStamp()).WithCurrentCulture();
            }
        }

        private static string NewSecurityStamp()
        {
            return Guid.NewGuid().ToString();
        }

        // IUserLoginStore methods
        private IUserLoginStore<TUser, TKey> GetLoginStore()
        {
            var cast = Store as IUserLoginStore<TUser, TKey>;
            if (cast == null)
            {
                throw new NotSupportedException(Resources.StoreNotIUserLoginStore);
            }
            return cast;
        }

        /// <summary>
        ///     Returns the user associated with this login
        /// </summary>
        /// <returns></returns>
        public virtual Task<TUser> FindAsync(UserLoginInfo login)
        {
            ThrowIfDisposed();
            return GetLoginStore().FindAsync(login);
        }

        /// <summary>
        ///     Remove a user login
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="login"></param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> RemoveLoginAsync(TKey userId, UserLoginInfo login)
        {
            ThrowIfDisposed();
            var loginStore = GetLoginStore();
            if (login == null)
            {
                throw new ArgumentNullException("login");
            }
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            await loginStore.RemoveLoginAsync(user, login).WithCurrentCulture();
            await UpdateSecurityStampInternal(user).WithCurrentCulture();
            return await UpdateAsync(user).WithCurrentCulture();
        }

        /// <summary>
        ///     Associate a login with a user
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="login"></param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> AddLoginAsync(TKey userId, UserLoginInfo login)
        {
            ThrowIfDisposed();
            var loginStore = GetLoginStore();
            if (login == null)
            {
                throw new ArgumentNullException("login");
            }
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            var existingUser = await FindAsync(login).WithCurrentCulture();
            if (existingUser != null)
            {
                return IdentityResult.Failed(Resources.ExternalLoginExists);
            }
            await loginStore.AddLoginAsync(user, login).WithCurrentCulture();
            return await UpdateAsync(user).WithCurrentCulture();
        }

        /// <summary>
        ///     Gets the logins for a user.
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public virtual async Task<IList<UserLoginInfo>> GetLoginsAsync(TKey userId)
        {
            ThrowIfDisposed();
            var loginStore = GetLoginStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            return await loginStore.GetLoginsAsync(user).WithCurrentCulture();
        }

        // IUserClaimStore methods
        private IUserClaimStore<TUser, TKey> GetClaimStore()
        {
            var cast = Store as IUserClaimStore<TUser, TKey>;
            if (cast == null)
            {
                throw new NotSupportedException(Resources.StoreNotIUserClaimStore);
            }
            return cast;
        }

        /// <summary>
        ///     Add a user claim
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="claim"></param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> AddClaimAsync(TKey userId, Claim claim)
        {
            ThrowIfDisposed();
            var claimStore = GetClaimStore();
            if (claim == null)
            {
                throw new ArgumentNullException("claim");
            }
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            await claimStore.AddClaimAsync(user, claim).WithCurrentCulture();
            return await UpdateAsync(user).WithCurrentCulture();
        }

        /// <summary>
        ///     Remove a user claim
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="claim"></param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> RemoveClaimAsync(TKey userId, Claim claim)
        {
            ThrowIfDisposed();
            var claimStore = GetClaimStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            await claimStore.RemoveClaimAsync(user, claim).WithCurrentCulture();
            return await UpdateAsync(user).WithCurrentCulture();
        }

        /// <summary>
        ///     Get a users's claims
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public virtual async Task<IList<Claim>> GetClaimsAsync(TKey userId)
        {
            ThrowIfDisposed();
            var claimStore = GetClaimStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            return await claimStore.GetClaimsAsync(user).WithCurrentCulture();
        }

        private IUserRoleStore<TUser, TKey> GetUserRoleStore()
        {
            var cast = Store as IUserRoleStore<TUser, TKey>;
            if (cast == null)
            {
                throw new NotSupportedException(Resources.StoreNotIUserRoleStore);
            }
            return cast;
        }

        /// <summary>
        ///     Add a user to a role
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="role"></param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> AddToRoleAsync(TKey userId, string role)
        {
            ThrowIfDisposed();
            var userRoleStore = GetUserRoleStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            var userRoles = await userRoleStore.GetRolesAsync(user).WithCurrentCulture();
            if (userRoles.Contains(role))
            {
                return new IdentityResult(Resources.UserAlreadyInRole);
            }
            await userRoleStore.AddToRoleAsync(user, role).WithCurrentCulture();
            return await UpdateAsync(user).WithCurrentCulture();
        }

        /// <summary>
        /// Method to add user to multiple roles
        /// </summary>
        /// <param name="userId">user id</param>
        /// <param name="roles">list of role names</param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> AddToRolesAsync(TKey userId, params string[] roles)
        {
            ThrowIfDisposed();
            var userRoleStore = GetUserRoleStore();
            if (roles == null)
            {
                throw new ArgumentNullException("roles");
            }
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            var userRoles = await userRoleStore.GetRolesAsync(user).WithCurrentCulture();
            foreach (var r in roles)
            {
                if (userRoles.Contains(r))
                {
                    return new IdentityResult(Resources.UserAlreadyInRole);
                }
                await userRoleStore.AddToRoleAsync(user, r).WithCurrentCulture();
            }
            return await UpdateAsync(user).WithCurrentCulture();
        }

        /// <summary>
        /// Remove user from multiple roles
        /// </summary>
        /// <param name="userId">user id</param>
        /// <param name="roles">list of role names</param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> RemoveFromRolesAsync(TKey userId, params string[] roles)
        {
            ThrowIfDisposed();
            var userRoleStore = GetUserRoleStore();
            if (roles == null)
            {
                throw new ArgumentNullException("roles");
            }
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }

            // Remove user to each role using UserRoleStore
            var userRoles = await userRoleStore.GetRolesAsync(user).WithCurrentCulture();
            foreach (var role in roles)
            {
                if (!userRoles.Contains(role))
                {
                    return new IdentityResult(Resources.UserNotInRole);
                }
                await userRoleStore.RemoveFromRoleAsync(user, role).WithCurrentCulture();
            }

            // Call update once when all roles are removed
            return await UpdateAsync(user).WithCurrentCulture();
        }

        /// <summary>
        ///     Remove a user from a role.
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="role"></param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> RemoveFromRoleAsync(TKey userId, string role)
        {
            ThrowIfDisposed();
            var userRoleStore = GetUserRoleStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            if (!await userRoleStore.IsInRoleAsync(user, role).WithCurrentCulture())
            {
                return new IdentityResult(Resources.UserNotInRole);
            }
            await userRoleStore.RemoveFromRoleAsync(user, role).WithCurrentCulture();
            return await UpdateAsync(user).WithCurrentCulture();
        }

        /// <summary>
        ///     Returns the roles for the user
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public virtual async Task<IList<string>> GetRolesAsync(TKey userId)
        {
            ThrowIfDisposed();
            var userRoleStore = GetUserRoleStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            return await userRoleStore.GetRolesAsync(user).WithCurrentCulture();
        }

        /// <summary>
        ///     Returns true if the user is in the specified role
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="role"></param>
        /// <returns></returns>
        public virtual async Task<bool> IsInRoleAsync(TKey userId, string role)
        {
            ThrowIfDisposed();
            var userRoleStore = GetUserRoleStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            return await userRoleStore.IsInRoleAsync(user, role).WithCurrentCulture();
        }

        // IUserEmailStore methods
        internal IUserEmailStore<TUser, TKey> GetEmailStore()
        {
            var cast = Store as IUserEmailStore<TUser, TKey>;
            if (cast == null)
            {
                throw new NotSupportedException(Resources.StoreNotIUserEmailStore);
            }
            return cast;
        }

        /// <summary>
        ///     Get a user's email
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public virtual async Task<string> GetEmailAsync(TKey userId)
        {
            ThrowIfDisposed();
            var store = GetEmailStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            return await store.GetEmailAsync(user).WithCurrentCulture();
        }

        /// <summary>
        ///     Set a user's email
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="email"></param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> SetEmailAsync(TKey userId, string email)
        {
            ThrowIfDisposed();
            var store = GetEmailStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            await store.SetEmailAsync(user, email).WithCurrentCulture();
            await store.SetEmailConfirmedAsync(user, false).WithCurrentCulture();
            await UpdateSecurityStampInternal(user).WithCurrentCulture();
            return await UpdateAsync(user).WithCurrentCulture();
        }

        /// <summary>
        ///     Find a user by his email
        /// </summary>
        /// <param name="email"></param>
        /// <returns></returns>
        public virtual Task<TUser> FindByEmailAsync(string email)
        {
            ThrowIfDisposed();
            var store = GetEmailStore();
            if (email == null)
            {
                throw new ArgumentNullException("email");
            }
            return store.FindByEmailAsync(email);
        }

        /// <summary>
        ///     Get the email confirmation token for the user
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public virtual Task<string> GenerateEmailConfirmationTokenAsync(TKey userId)
        {
            ThrowIfDisposed();
            return GenerateUserTokenAsync("Confirmation", userId);
        }

        /// <summary>
        ///     Confirm the user's email with confirmation token
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> ConfirmEmailAsync(TKey userId, string token)
        {
            ThrowIfDisposed();
            var store = GetEmailStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            if (!await VerifyUserTokenAsync(userId, "Confirmation", token).WithCurrentCulture())
            {
                return IdentityResult.Failed(Resources.InvalidToken);
            }
            await store.SetEmailConfirmedAsync(user, true).WithCurrentCulture();
            return await UpdateAsync(user).WithCurrentCulture();
        }

        /// <summary>
        ///     Returns true if the user's email has been confirmed
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public virtual async Task<bool> IsEmailConfirmedAsync(TKey userId)
        {
            ThrowIfDisposed();
            var store = GetEmailStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            return await store.GetEmailConfirmedAsync(user).WithCurrentCulture();
        }

        // IUserPhoneNumberStore methods
        internal IUserPhoneNumberStore<TUser, TKey> GetPhoneNumberStore()
        {
            var cast = Store as IUserPhoneNumberStore<TUser, TKey>;
            if (cast == null)
            {
                throw new NotSupportedException(Resources.StoreNotIUserPhoneNumberStore);
            }
            return cast;
        }

        /// <summary>
        ///     Get a user's phoneNumber
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public virtual async Task<string> GetPhoneNumberAsync(TKey userId)
        {
            ThrowIfDisposed();
            var store = GetPhoneNumberStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            return await store.GetPhoneNumberAsync(user).WithCurrentCulture();
        }

        /// <summary>
        ///     Set a user's phoneNumber
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="phoneNumber"></param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> SetPhoneNumberAsync(TKey userId, string phoneNumber)
        {
            ThrowIfDisposed();
            var store = GetPhoneNumberStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            await store.SetPhoneNumberAsync(user, phoneNumber).WithCurrentCulture();
            await store.SetPhoneNumberConfirmedAsync(user, false).WithCurrentCulture();
            await UpdateSecurityStampInternal(user).WithCurrentCulture();
            return await UpdateAsync(user).WithCurrentCulture();
        }

        /// <summary>
        ///     Set a user's phoneNumber with the verification token
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="phoneNumber"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> ChangePhoneNumberAsync(TKey userId, string phoneNumber, string token)
        {
            ThrowIfDisposed();
            var store = GetPhoneNumberStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            if (await VerifyChangePhoneNumberTokenAsync(userId, token, phoneNumber).WithCurrentCulture())
            {
                await store.SetPhoneNumberAsync(user, phoneNumber).WithCurrentCulture();
                await store.SetPhoneNumberConfirmedAsync(user, true).WithCurrentCulture();
                await UpdateSecurityStampInternal(user).WithCurrentCulture();
                return await UpdateAsync(user).WithCurrentCulture();
            }
            return IdentityResult.Failed(Resources.InvalidToken);
        }

        /// <summary>
        ///     Returns true if the user's phone number has been confirmed
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public virtual async Task<bool> IsPhoneNumberConfirmedAsync(TKey userId)
        {
            ThrowIfDisposed();
            var store = GetPhoneNumberStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            return await store.GetPhoneNumberConfirmedAsync(user).WithCurrentCulture();
        }

        // Two factor APIS

        internal async Task<SecurityToken> CreateSecurityTokenAsync(TKey userId)
        {
            return
                new SecurityToken(Encoding.Unicode.GetBytes(await GetSecurityStampAsync(userId).WithCurrentCulture()));
        }

        /// <summary>
        ///     Generate a code that the user can use to change their phone number to a specific number
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="phoneNumber"></param>
        /// <returns></returns>
        public virtual async Task<string> GenerateChangePhoneNumberTokenAsync(TKey userId, string phoneNumber)
        {
            ThrowIfDisposed();
            return
                Rfc6238AuthenticationService.GenerateCode(await CreateSecurityTokenAsync(userId).WithCurrentCulture(), phoneNumber)
                    .ToString("D6", CultureInfo.InvariantCulture);
        }

        /// <summary>
        ///     Verify the code is valid for a specific user and for a specific phone number
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="token"></param>
        /// <param name="phoneNumber"></param>
        /// <returns></returns>
        public virtual async Task<bool> VerifyChangePhoneNumberTokenAsync(TKey userId, string token, string phoneNumber)
        {
            ThrowIfDisposed();
            var securityToken = await CreateSecurityTokenAsync(userId).WithCurrentCulture();
            int code;
            if (securityToken != null && Int32.TryParse(token, out code))
            {
                return Rfc6238AuthenticationService.ValidateCode(securityToken, code, phoneNumber);
            }
            return false;
        }

        /// <summary>
        ///     Verify a user token with the specified purpose
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="purpose"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        public virtual async Task<bool> VerifyUserTokenAsync(TKey userId, string purpose, string token)
        {
            ThrowIfDisposed();
            if (UserTokenProvider == null)
            {
                throw new NotSupportedException(Resources.NoTokenProvider);
            }
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            // Make sure the token is valid
            return await UserTokenProvider.ValidateAsync(purpose, token, this, user).WithCurrentCulture();
        }

        /// <summary>
        ///     Get a user token for a specific purpose
        /// </summary>
        /// <param name="purpose"></param>
        /// <param name="userId"></param>
        /// <returns></returns>
        public virtual async Task<string> GenerateUserTokenAsync(string purpose, TKey userId)
        {
            ThrowIfDisposed();
            if (UserTokenProvider == null)
            {
                throw new NotSupportedException(Resources.NoTokenProvider);
            }
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            return await UserTokenProvider.GenerateAsync(purpose, this, user).WithCurrentCulture();
        }

        /// <summary>
        ///     Register a two factor authentication provider with the TwoFactorProviders mapping
        /// </summary>
        /// <param name="twoFactorProvider"></param>
        /// <param name="provider"></param>
        public virtual void RegisterTwoFactorProvider(string twoFactorProvider, IUserTokenProvider<TUser, TKey> provider)
        {
            ThrowIfDisposed();
            if (twoFactorProvider == null)
            {
                throw new ArgumentNullException("twoFactorProvider");
            }
            if (provider == null)
            {
                throw new ArgumentNullException("provider");
            }
            TwoFactorProviders[twoFactorProvider] = provider;
        }

        /// <summary>
        ///     Returns a list of valid two factor providers for a user
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public virtual async Task<IList<string>> GetValidTwoFactorProvidersAsync(TKey userId)
        {
            ThrowIfDisposed();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            var results = new List<string>();
            foreach (var f in TwoFactorProviders)
            {
                if (await f.Value.IsValidProviderForUserAsync(this, user).WithCurrentCulture())
                {
                    results.Add(f.Key);
                }
            }
            return results;
        }

        /// <summary>
        ///     Verify a two factor token with the specified provider
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="twoFactorProvider"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        public virtual async Task<bool> VerifyTwoFactorTokenAsync(TKey userId, string twoFactorProvider, string token)
        {
            ThrowIfDisposed();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            if (!_factors.ContainsKey(twoFactorProvider))
            {
                throw new NotSupportedException(String.Format(CultureInfo.CurrentCulture, Resources.NoTwoFactorProvider,
                    twoFactorProvider));
            }
            // Make sure the token is valid
            var provider = _factors[twoFactorProvider];
            return await provider.ValidateAsync(twoFactorProvider, token, this, user).WithCurrentCulture();
        }

        /// <summary>
        ///     Get a token for a specific two factor provider
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="twoFactorProvider"></param>
        /// <returns></returns>
        public virtual async Task<string> GenerateTwoFactorTokenAsync(TKey userId, string twoFactorProvider)
        {
            ThrowIfDisposed();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            if (!_factors.ContainsKey(twoFactorProvider))
            {
                throw new NotSupportedException(String.Format(CultureInfo.CurrentCulture, Resources.NoTwoFactorProvider,
                    twoFactorProvider));
            }
            return await _factors[twoFactorProvider].GenerateAsync(twoFactorProvider, this, user).WithCurrentCulture();
        }

        /// <summary>
        ///     Notify a user with a token using a specific two-factor authentication provider's Notify method
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="twoFactorProvider"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> NotifyTwoFactorTokenAsync(TKey userId, string twoFactorProvider,
            string token)
        {
            ThrowIfDisposed();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            if (!_factors.ContainsKey(twoFactorProvider))
            {
                throw new NotSupportedException(String.Format(CultureInfo.CurrentCulture, Resources.NoTwoFactorProvider,
                    twoFactorProvider));
            }
            await _factors[twoFactorProvider].NotifyAsync(token, this, user).WithCurrentCulture();
            return IdentityResult.Success;
        }

        // IUserFactorStore methods
        internal IUserTwoFactorStore<TUser, TKey> GetUserTwoFactorStore()
        {
            var cast = Store as IUserTwoFactorStore<TUser, TKey>;
            if (cast == null)
            {
                throw new NotSupportedException(Resources.StoreNotIUserTwoFactorStore);
            }
            return cast;
        }

        /// <summary>
        ///     Get whether two factor authentication is enabled for a user
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public virtual async Task<bool> GetTwoFactorEnabledAsync(TKey userId)
        {
            ThrowIfDisposed();
            var store = GetUserTwoFactorStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            return await store.GetTwoFactorEnabledAsync(user).WithCurrentCulture();
        }

        /// <summary>
        ///     Set whether a user has two factor authentication enabled
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="enabled"></param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> SetTwoFactorEnabledAsync(TKey userId, bool enabled)
        {
            ThrowIfDisposed();
            var store = GetUserTwoFactorStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            await store.SetTwoFactorEnabledAsync(user, enabled).WithCurrentCulture();
            await UpdateSecurityStampInternal(user).WithCurrentCulture();
            return await UpdateAsync(user).WithCurrentCulture();
        }

        // SMS/Email methods

        /// <summary>
        ///     Send an email to the user
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="subject"></param>
        /// <param name="body"></param>
        /// <returns></returns>
        public virtual async Task SendEmailAsync(TKey userId, string subject, string body)
        {
            ThrowIfDisposed();
            if (EmailService != null)
            {
                var msg = new IdentityMessage
                {
                    Destination = await GetEmailAsync(userId).WithCurrentCulture(),
                    Subject = subject,
                    Body = body,
                };
                await EmailService.SendAsync(msg).WithCurrentCulture();
            }
        }

        /// <summary>
        ///     Send a user a sms message
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="message"></param>
        /// <returns></returns>
        public virtual async Task SendSmsAsync(TKey userId, string message)
        {
            ThrowIfDisposed();
            if (SmsService != null)
            {
                var msg = new IdentityMessage
                {
                    Destination = await GetPhoneNumberAsync(userId).WithCurrentCulture(),
                    Body = message
                };
                await SmsService.SendAsync(msg).WithCurrentCulture();
            }
        }

        // IUserLockoutStore methods
        internal IUserLockoutStore<TUser, TKey> GetUserLockoutStore()
        {
            var cast = Store as IUserLockoutStore<TUser, TKey>;
            if (cast == null)
            {
                throw new NotSupportedException(Resources.StoreNotIUserLockoutStore);
            }
            return cast;
        }

        /// <summary>
        ///     Returns true if the user is locked out
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public virtual async Task<bool> IsLockedOutAsync(TKey userId)
        {
            ThrowIfDisposed();
            var store = GetUserLockoutStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            if (!await store.GetLockoutEnabledAsync(user).WithCurrentCulture())
            {
                return false;
            }
            var lockoutTime = await store.GetLockoutEndDateAsync(user).WithCurrentCulture();
            return lockoutTime >= DateTimeOffset.UtcNow;
        }

        /// <summary>
        ///     Sets whether lockout is enabled for this user
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="enabled"></param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> SetLockoutEnabledAsync(TKey userId, bool enabled)
        {
            ThrowIfDisposed();
            var store = GetUserLockoutStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            await store.SetLockoutEnabledAsync(user, enabled).WithCurrentCulture();
            return await UpdateAsync(user).WithCurrentCulture();
        }

        /// <summary>
        ///     Returns whether lockout is enabled for the user
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public virtual async Task<bool> GetLockoutEnabledAsync(TKey userId)
        {
            ThrowIfDisposed();
            var store = GetUserLockoutStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            return await store.GetLockoutEnabledAsync(user).WithCurrentCulture();
        }

        /// <summary>
        ///     Returns when the user is no longer locked out, dates in the past are considered as not being locked out
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public virtual async Task<DateTimeOffset> GetLockoutEndDateAsync(TKey userId)
        {
            ThrowIfDisposed();
            var store = GetUserLockoutStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            return await store.GetLockoutEndDateAsync(user).WithCurrentCulture();
        }

        /// <summary>
        ///     Sets the when a user lockout ends
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="lockoutEnd"></param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> SetLockoutEndDateAsync(TKey userId, DateTimeOffset lockoutEnd)
        {
            ThrowIfDisposed();
            var store = GetUserLockoutStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            if (!await store.GetLockoutEnabledAsync(user).WithCurrentCulture())
            {
                return IdentityResult.Failed(Resources.LockoutNotEnabled);
            }
            await store.SetLockoutEndDateAsync(user, lockoutEnd).WithCurrentCulture();
            return await UpdateAsync(user).WithCurrentCulture();
        }

        /// <summary>
        /// Increments the access failed count for the user and if the failed access account is greater than or equal
        /// to the MaxFailedAccessAttempsBeforeLockout, the user will be locked out for the next DefaultAccountLockoutTimeSpan
        /// and the AccessFailedCount will be reset to 0. This is used for locking out the user account.
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> AccessFailedAsync(TKey userId)
        {
            ThrowIfDisposed();
            var store = GetUserLockoutStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            // If this puts the user over the threshold for lockout, lock them out and reset the access failed count
            var count = await store.IncrementAccessFailedCountAsync(user).WithCurrentCulture();
            if (count >= MaxFailedAccessAttemptsBeforeLockout)
            {
                await
                    store.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.Add(DefaultAccountLockoutTimeSpan))
                        .WithCurrentCulture();
                await store.ResetAccessFailedCountAsync(user).WithCurrentCulture();
            }
            return await UpdateAsync(user).WithCurrentCulture();
        }

        /// <summary>
        ///     Resets the access failed count for the user to 0
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> ResetAccessFailedCountAsync(TKey userId)
        {
            ThrowIfDisposed();
            var store = GetUserLockoutStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }

            if (await GetAccessFailedCountAsync(user.Id).WithCurrentCulture() == 0)
            {
                return IdentityResult.Success;
            }

            await store.ResetAccessFailedCountAsync(user).WithCurrentCulture();
            return await UpdateAsync(user).WithCurrentCulture();
        }

        /// <summary>
        ///     Returns the number of failed access attempts for the user
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public virtual async Task<int> GetAccessFailedCountAsync(TKey userId)
        {
            ThrowIfDisposed();
            var store = GetUserLockoutStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, Resources.UserIdNotFound,
                    userId));
            }
            return await store.GetAccessFailedCountAsync(user).WithCurrentCulture();
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().Name);
            }
        }

        /// <summary>
        ///     When disposing, actually dipose the store
        /// </summary>
        /// <param name="disposing"></param>
        protected virtual void Dispose(bool disposing)
        {
            if (disposing && !_disposed)
            {
                Store.Dispose();
                _disposed = true;
            }
        }
    }
}