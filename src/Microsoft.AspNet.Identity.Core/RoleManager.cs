// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Linq;
using System.Threading.Tasks;

namespace Microsoft.AspNet.Identity
{
    /// <summary>
    ///     Exposes role related api which will automatically save changes to the RoleStore
    /// </summary>
    /// <typeparam name="TRole"></typeparam>
    public class RoleManager<TRole> : RoleManager<TRole, string> where TRole : class, IRole<string>
    {
        /// <summary>
        ///     Constructor
        /// </summary>
        /// <param name="store"></param>
        public RoleManager(IRoleStore<TRole, string> store)
            : base(store)
        {
        }
    }

    /// <summary>
    ///     Exposes role related api which will automatically save changes to the RoleStore
    /// </summary>
    /// <typeparam name="TRole"></typeparam>
    /// <typeparam name="TKey"></typeparam>
    public class RoleManager<TRole, TKey> : IDisposable
        where TRole : class, IRole<TKey>
        where TKey : IEquatable<TKey>
    {
        private bool _disposed;
        private IIdentityValidator<TRole> _roleValidator;

        /// <summary>
        ///     Constructor
        /// </summary>
        /// <param name="store">The IRoleStore is responsible for commiting changes via the UpdateAsync/CreateAsync methods</param>
        public RoleManager(IRoleStore<TRole, TKey> store)
        {
            if (store == null)
            {
                throw new ArgumentNullException("store");
            }
            Store = store;
            RoleValidator = new RoleValidator<TRole, TKey>(this);
        }

        /// <summary>
        ///     Persistence abstraction that the Manager operates against
        /// </summary>
        protected IRoleStore<TRole, TKey> Store { get; private set; }

        /// <summary>
        ///     Used to validate roles before persisting changes
        /// </summary>
        public IIdentityValidator<TRole> RoleValidator
        {
            get { return _roleValidator; }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException("value");
                }
                _roleValidator = value;
            }
        }

        /// <summary>
        ///     Returns an IQueryable of roles if the store is an IQueryableRoleStore
        /// </summary>
        public virtual IQueryable<TRole> Roles
        {
            get
            {
                var queryableStore = Store as IQueryableRoleStore<TRole, TKey>;
                if (queryableStore == null)
                {
                    throw new NotSupportedException(Resources.StoreNotIQueryableRoleStore);
                }
                return queryableStore.Roles;
            }
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
        ///     Create a role
        /// </summary>
        /// <param name="role"></param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> CreateAsync(TRole role)
        {
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException("role");
            }

            var result = await RoleValidator.ValidateAsync(role).WithCurrentCulture();
            if (!result.Succeeded)
            {
                return result;
            }
            await Store.CreateAsync(role).WithCurrentCulture();
            return IdentityResult.Success;
        }

        /// <summary>
        ///     Update an existing role
        /// </summary>
        /// <param name="role"></param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> UpdateAsync(TRole role)
        {
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException("role");
            }

            var result = await RoleValidator.ValidateAsync(role).WithCurrentCulture();
            if (!result.Succeeded)
            {
                return result;
            }
            await Store.UpdateAsync(role).WithCurrentCulture();
            return IdentityResult.Success;
        }

        /// <summary>
        ///     Delete a role
        /// </summary>
        /// <param name="role"></param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> DeleteAsync(TRole role)
        {
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException("role");
            }

            await Store.DeleteAsync(role).WithCurrentCulture();
            return IdentityResult.Success;
        }

        /// <summary>
        ///     Returns true if the role exists
        /// </summary>
        /// <param name="roleName"></param>
        /// <returns></returns>
        public virtual async Task<bool> RoleExistsAsync(string roleName)
        {
            ThrowIfDisposed();
            if (roleName == null)
            {
                throw new ArgumentNullException("roleName");
            }

            return await FindByNameAsync(roleName).WithCurrentCulture() != null;
        }

        /// <summary>
        ///     Find a role by id
        /// </summary>
        /// <param name="roleId"></param>
        /// <returns></returns>
        public virtual async Task<TRole> FindByIdAsync(TKey roleId)
        {
            ThrowIfDisposed();
            return await Store.FindByIdAsync(roleId).WithCurrentCulture();
        }

        /// <summary>
        ///     Find a role by name
        /// </summary>
        /// <param name="roleName"></param>
        /// <returns></returns>
        public virtual async Task<TRole> FindByNameAsync(string roleName)
        {
            ThrowIfDisposed();
            if (roleName == null)
            {
                throw new ArgumentNullException("roleName");
            }

            return await Store.FindByNameAsync(roleName).WithCurrentCulture();
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
            }
            _disposed = true;
        }
    }
}