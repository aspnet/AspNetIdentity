using System;

namespace Microsoft.AspNet.Identity
{
    /// <summary>
    ///     Extension methods for RoleManager
    /// </summary>
    public static class RoleManagerExtensions
    {
        /// <summary>
        ///     Find a role by id
        /// </summary>
        /// <param name="manager"></param>
        /// <param name="roleId"></param>
        /// <returns></returns>
        public static TRole FindById<TRole, TKey>(this RoleManager<TRole, TKey> manager, TKey roleId)
            where TKey : IEquatable<TKey>
            where TRole : class, IRole<TKey>
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }
            return AsyncHelper.RunSync(() => manager.FindByIdAsync(roleId));
        }

        /// <summary>
        ///     Find a role by name
        /// </summary>
        /// <param name="manager"></param>
        /// <param name="roleName"></param>
        /// <returns></returns>
        public static TRole FindByName<TRole, TKey>(this RoleManager<TRole, TKey> manager, string roleName)
            where TKey : IEquatable<TKey>
            where TRole : class, IRole<TKey>
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }
            return AsyncHelper.RunSync(() => manager.FindByNameAsync(roleName));
        }

        /// <summary>
        ///     Create a role
        /// </summary>
        /// <param name="manager"></param>
        /// <param name="role"></param>
        /// <returns></returns>
        public static IdentityResult Create<TRole, TKey>(this RoleManager<TRole, TKey> manager, TRole role)
            where TKey : IEquatable<TKey>
            where TRole : class, IRole<TKey>
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }
            return AsyncHelper.RunSync(() => manager.CreateAsync(role));
        }

        /// <summary>
        ///     Update an existing role
        /// </summary>
        /// <param name="manager"></param>
        /// <param name="role"></param>
        /// <returns></returns>
        public static IdentityResult Update<TRole, TKey>(this RoleManager<TRole, TKey> manager, TRole role)
            where TKey : IEquatable<TKey>
            where TRole : class, IRole<TKey>
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }
            return AsyncHelper.RunSync(() => manager.UpdateAsync(role));
        }

        /// <summary>
        ///     Delete a role
        /// </summary>
        /// <param name="manager"></param>
        /// <param name="role"></param>
        /// <returns></returns>
        public static IdentityResult Delete<TRole, TKey>(this RoleManager<TRole, TKey> manager, TRole role)
            where TKey : IEquatable<TKey>
            where TRole : class, IRole<TKey>
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }
            return AsyncHelper.RunSync(() => manager.DeleteAsync(role));
        }

        /// <summary>
        ///     Returns true if the role exists
        /// </summary>
        /// <param name="manager"></param>
        /// <param name="roleName"></param>
        /// <returns></returns>
        public static bool RoleExists<TRole, TKey>(this RoleManager<TRole, TKey> manager, string roleName)
            where TKey : IEquatable<TKey>
            where TRole : class, IRole<TKey>
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }
            return AsyncHelper.RunSync(() => manager.RoleExistsAsync(roleName));
        }
    }
}