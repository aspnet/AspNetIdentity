// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;

namespace Identity.Test
{
    public class InMemoryUser : IUser<string>
    {
        private readonly IList<Claim> _claims;
        private readonly IList<UserLoginInfo> _logins;
        private readonly IList<string> _roles;

        public InMemoryUser(string name)
        {
            Id = Guid.NewGuid().ToString();
            _logins = new List<UserLoginInfo>();
            _claims = new List<Claim>();
            _roles = new List<string>();
            UserName = name;
        }

        /// <summary>
        ///     Email
        /// </summary>
        public virtual string Email { get; set; }

        /// <summary>
        ///     True if the email is confirmed, default is false
        /// </summary>
        public virtual bool EmailConfirmed { get; set; }

        /// <summary>
        ///     The salted/hashed form of the user password
        /// </summary>
        public virtual string PasswordHash { get; set; }

        /// <summary>
        ///     A random value that should change whenever a users credentials have changed (password changed, login removed)
        /// </summary>
        public virtual string SecurityStamp { get; set; }

        /// <summary>
        ///     PhoneNumber for the user
        /// </summary>
        public virtual string PhoneNumber { get; set; }

        /// <summary>
        ///     True if the phone number is confirmed, default is false
        /// </summary>
        public virtual bool PhoneNumberConfirmed { get; set; }

        /// <summary>
        ///     Is two factor enabled for the user
        /// </summary>
        public virtual bool TwoFactorEnabled { get; set; }

        /// <summary>
        ///     DateTime in UTC when lockout ends, any time in the past is considered not locked out.
        /// </summary>
        public virtual DateTimeOffset LockoutEnd { get; set; }

        /// <summary>
        ///     Is lockout enabled for this user
        /// </summary>
        public virtual bool LockoutEnabled { get; set; }

        /// <summary>
        ///     Used to record failures for the purposes of lockout
        /// </summary>
        public virtual int AccessFailedCount { get; set; }

        public IList<UserLoginInfo> Logins
        {
            get { return _logins; }
        }

        public IList<Claim> Claims
        {
            get { return _claims; }
        }

        public IList<string> Roles
        {
            get { return _roles; }
        }

        public virtual string Id { get; set; }
        public virtual string UserName { get; set; }
    }

    public class InMemoryRole : IRole
    {
        public InMemoryRole(string roleName)
        {
            Id = Guid.NewGuid().ToString();
            Name = roleName;
        }

        public virtual string Id { get; set; }
        public virtual string Name { get; set; }
    }

    public class LoginComparer : IEqualityComparer<UserLoginInfo>
    {
        public bool Equals(UserLoginInfo x, UserLoginInfo y)
        {
            return x.LoginProvider == y.LoginProvider && x.ProviderKey == y.ProviderKey;
        }


        public int GetHashCode(UserLoginInfo obj)
        {
            return (obj.ProviderKey + "--" + obj.LoginProvider).GetHashCode();
        }
    }

    public class InMemoryUserStore : 
        IUserStore<InMemoryUser>, 
        IUserLoginStore<InMemoryUser>, 
        IUserRoleStore<InMemoryUser>,
        IUserClaimStore<InMemoryUser>, 
        IUserPasswordStore<InMemoryUser>, 
        IUserSecurityStampStore<InMemoryUser>,
        IUserEmailStore<InMemoryUser>,
        IUserLockoutStore<InMemoryUser, string>,
        IUserPhoneNumberStore<InMemoryUser>

    {
        private readonly Dictionary<UserLoginInfo, InMemoryUser> _logins =
            new Dictionary<UserLoginInfo, InMemoryUser>(new LoginComparer());

        private readonly Dictionary<string, InMemoryUser> _users = new Dictionary<string, InMemoryUser>();

        public IQueryable<InMemoryUser> Users
        {
            get { return _users.Values.AsQueryable(); }
        }

        public Task<IList<Claim>> GetClaimsAsync(InMemoryUser user)
        {
            return Task.FromResult(user.Claims);
        }

        public Task AddClaimAsync(InMemoryUser user, Claim claim)
        {
            user.Claims.Add(claim);
            return Task.FromResult(0);
        }

        public Task RemoveClaimAsync(InMemoryUser user, Claim claim)
        {
            user.Claims.Remove(claim);
            return Task.FromResult(0);
        }

        public Task AddLoginAsync(InMemoryUser user, UserLoginInfo login)
        {
            user.Logins.Add(login);
            _logins[login] = user;
            return Task.FromResult(0);
        }

        public Task RemoveLoginAsync(InMemoryUser user, UserLoginInfo login)
        {
            var logs =
                user.Logins.Where(l => l.ProviderKey == login.ProviderKey && l.LoginProvider == login.LoginProvider)
                .ToList();
            foreach (var l in logs)
            {
                user.Logins.Remove(l);
                _logins[l] = null;
            }
            return Task.FromResult(0);
        }

        public Task<IList<UserLoginInfo>> GetLoginsAsync(InMemoryUser user)
        {
            return Task.FromResult(user.Logins);
        }

        public Task<InMemoryUser> FindAsync(UserLoginInfo login)
        {
            if (_logins.ContainsKey(login))
            {
                return Task.FromResult(_logins[login]);
            }
            return Task.FromResult<InMemoryUser>(null);
        }

        public Task SetPasswordHashAsync(InMemoryUser user, string passwordHash)
        {
            user.PasswordHash = passwordHash;
            return Task.FromResult(0);
        }

        public Task<string> GetPasswordHashAsync(InMemoryUser user)
        {
            return Task.FromResult(user.PasswordHash);
        }

        public Task<bool> HasPasswordAsync(InMemoryUser user)
        {
            return Task.FromResult(user.PasswordHash != null);
        }

        public Task AddToRoleAsync(InMemoryUser user, string role)
        {
            user.Roles.Add(role);
            return Task.FromResult(0);
        }

        public Task RemoveFromRoleAsync(InMemoryUser user, string role)
        {
            user.Roles.Remove(role);
            return Task.FromResult(0);
        }

        public Task<IList<string>> GetRolesAsync(InMemoryUser user)
        {
            return Task.FromResult(user.Roles);
        }

        public Task<bool> IsInRoleAsync(InMemoryUser user, string role)
        {
            return Task.FromResult(user.Roles.Contains(role));
        }

        public Task SetSecurityStampAsync(InMemoryUser user, string stamp)
        {
            user.SecurityStamp = stamp;
            return Task.FromResult(0);
        }

        public Task<string> GetSecurityStampAsync(InMemoryUser user)
        {
            return Task.FromResult(user.SecurityStamp);
        }

        public Task CreateAsync(InMemoryUser user)
        {
            _users[user.Id] = user;
            return Task.FromResult(0);
        }

        public Task UpdateAsync(InMemoryUser user)
        {
            _users[user.Id] = user;
            return Task.FromResult(0);
        }

        public Task<InMemoryUser> FindByIdAsync(string userId)
        {
            if (_users.ContainsKey(userId))
            {
                return Task.FromResult(_users[userId]);
            }
            return Task.FromResult<InMemoryUser>(null);
        }

        public void Dispose()
        {
        }

        public Task<InMemoryUser> FindByNameAsync(string userName)
        {
            return Task.FromResult(Users.FirstOrDefault(u => String.Equals(u.UserName, userName, StringComparison.OrdinalIgnoreCase)));
        }

        public Task DeleteAsync(InMemoryUser user)
        {
            if (user == null || !_users.ContainsKey(user.Id))
            {
                throw new InvalidOperationException("Unknown user");
            }
            _users.Remove(user.Id);
            return Task.FromResult(0);
        }

        public Task SetEmailAsync(InMemoryUser user, string email)
        {
            user.Email = email;
            return Task.FromResult(0);
        }

        public Task<string> GetEmailAsync(InMemoryUser user)
        {
            return Task.FromResult(user.Email);
        }

        public Task<bool> GetEmailConfirmedAsync(InMemoryUser user)
        {
            return Task.FromResult(user.EmailConfirmed);
        }

        public Task SetEmailConfirmedAsync(InMemoryUser user, bool confirmed)
        {
            user.EmailConfirmed = confirmed;
            return Task.FromResult(0);
        }

        public Task<InMemoryUser> FindByEmailAsync(string email)
        {
            return Task.FromResult(Users.FirstOrDefault(u => String.Equals(u.Email, email, StringComparison.OrdinalIgnoreCase)));
        }

        public Task<DateTimeOffset> GetLockoutEndDateAsync(InMemoryUser user)
        {
            return Task.FromResult(user.LockoutEnd);
        }

        public Task SetLockoutEndDateAsync(InMemoryUser user, DateTimeOffset lockoutEnd)
        {
            user.LockoutEnd = lockoutEnd;
            return Task.FromResult(0);
        }

        public Task<int> IncrementAccessFailedCountAsync(InMemoryUser user)
        {
            user.AccessFailedCount++;
            return Task.FromResult(user.AccessFailedCount);
        }

        public Task ResetAccessFailedCountAsync(InMemoryUser user)
        {
            user.AccessFailedCount = 0;
            return Task.FromResult(0);
        }

        public Task<int> GetAccessFailedCountAsync(InMemoryUser user)
        {
            return Task.FromResult(user.AccessFailedCount);
        }

        public Task<bool> GetLockoutEnabledAsync(InMemoryUser user)
        {
            return Task.FromResult(user.LockoutEnabled);
        }

        public Task SetLockoutEnabledAsync(InMemoryUser user, bool enabled)
        {
            user.LockoutEnabled = enabled;
            return Task.FromResult(0);
        }

        public Task SetPhoneNumberAsync(InMemoryUser user, string phoneNumber)
        {
            user.PhoneNumber = phoneNumber;
            return Task.FromResult(0);
        }

        public Task<string> GetPhoneNumberAsync(InMemoryUser user)
        {
            return Task.FromResult(user.PhoneNumber);
        }

        public Task<bool> GetPhoneNumberConfirmedAsync(InMemoryUser user)
        {
            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        public Task SetPhoneNumberConfirmedAsync(InMemoryUser user, bool confirmed)
        {
            user.PhoneNumberConfirmed = confirmed;
            return Task.FromResult(0);
        }
    }

    public class InMemoryRoleStore : IRoleStore<InMemoryRole>, IQueryableRoleStore<InMemoryRole>
    {
        private readonly Dictionary<string, InMemoryRole> _roles = new Dictionary<string, InMemoryRole>();

        public Task CreateAsync(InMemoryRole role)
        {
            _roles[role.Id] = role;
            return Task.FromResult(0);
        }

        public Task DeleteAsync(InMemoryRole role)
        {
            if (role == null || !_roles.ContainsKey(role.Id))
            {
                throw new InvalidOperationException("Unknown role");
            }
            _roles.Remove(role.Id);
            return Task.FromResult(0);
        }

        public Task UpdateAsync(InMemoryRole role)
        {
            _roles[role.Id] = role;
            return Task.FromResult(0);
        }

        public Task<InMemoryRole> FindByIdAsync(string roleId)
        {
            if (_roles.ContainsKey(roleId))
            {
                return Task.FromResult(_roles[roleId]);
            }
            return Task.FromResult<InMemoryRole>(null);
        }

        public Task<InMemoryRole> FindByNameAsync(string roleName)
        {
            return Task.FromResult(Roles.SingleOrDefault(r => String.Equals(r.Name, roleName, StringComparison.OrdinalIgnoreCase)));
        }

        public void Dispose()
        {
        }

        public IQueryable<InMemoryRole> Roles { get { return _roles.Values.AsQueryable(); } }
    }
}