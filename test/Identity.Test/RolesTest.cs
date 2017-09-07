// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Data.Entity.Validation;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Xunit;

namespace Identity.Test
{
    public class RolesTest
    {
        [Fact]
        public void ManagerPublicNullCheckTest()
        {
            ExceptionHelper.ThrowsArgumentNull(() => new RoleValidator<IdentityRole>(null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => new RoleManager<IdentityRole>(null), "store");
            var manager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>());
            ExceptionHelper.ThrowsArgumentNull(() => manager.RoleValidator = null, "value");
            ExceptionHelper.ThrowsArgumentNull(() => new RoleManager<IdentityRole>(null), "store");
            ExceptionHelper.ThrowsArgumentNull(
                () => AsyncHelper.RunSync(() => manager.RoleValidator.ValidateAsync(null)), "item");
            ExceptionHelper.ThrowsArgumentNull(() => manager.Create(null), "role");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => manager.UpdateAsync(null)), "role");
            ExceptionHelper.ThrowsArgumentNull(() => manager.Update(null), "role");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => manager.RoleExistsAsync(null)),
                "roleName");
            ExceptionHelper.ThrowsArgumentNull(() => manager.RoleExists(null), "roleName");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => manager.FindByNameAsync(null)),
                "roleName");
            ExceptionHelper.ThrowsArgumentNull(() => manager.FindByName(null), "roleName");
        }

        [Fact]
        public void RoleManagerMethodsThrowWhenDisposedTest()
        {
            var manager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>());
            manager.Dispose();
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => manager.CreateAsync(null)));
            Assert.Throws<ObjectDisposedException>(() => manager.Create(null));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => manager.UpdateAsync(null)));
            Assert.Throws<ObjectDisposedException>(() => manager.Update(null));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => manager.DeleteAsync(null)));
            Assert.Throws<ObjectDisposedException>(() => manager.Delete(null));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => manager.FindByIdAsync(null)));
            Assert.Throws<ObjectDisposedException>(() => manager.FindById(null));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => manager.FindByNameAsync(null)));
            Assert.Throws<ObjectDisposedException>(() => manager.FindByName(null));
        }

        [Fact]
        public void RoleStoreMethodsThrowWhenDisposedTest()
        {
            var store = new RoleStore<IdentityRole>();
            store.Dispose();
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => store.CreateAsync(null)));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => store.UpdateAsync(null)));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => store.DeleteAsync(null)));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => store.FindByIdAsync(null)));
            Assert.Throws<ObjectDisposedException>(() => AsyncHelper.RunSync(() => store.FindByNameAsync(null)));
        }

        [Fact]
        public void RoleManagerSyncMethodsThrowWhenManagerNullTest()
        {
            RoleManager<IdentityRole> manager = null;
            ExceptionHelper.ThrowsArgumentNull(() => manager.Create(null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.Update(null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.Delete(null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.FindById(null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.FindByName(null), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.RoleExists(null), "manager");
        }

        [Fact]
        public void RoleStorePublicNullCheckTest()
        {
            ExceptionHelper.ThrowsArgumentNull(() => new RoleStore<IdentityRole>(null), "context");
            var store = new RoleStore<IdentityRole>();
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => store.CreateAsync(null)), "role");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => store.UpdateAsync(null)), "role");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => store.DeleteAsync(null)), "role");
        }

        [Fact]
        public void RolesQueryableFailWhenStoreNotImplementedTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var manager = new RoleManager<IdentityRole>(new NoopRoleStore());
            Assert.Throws<NotSupportedException>(() => manager.Roles.Count());
        }

        [Fact]
        public async Task CreateRoleTest()
        {
            var manager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(UnitTestHelper.CreateDefaultDb()));
            var role = new IdentityRole("create");
            Assert.False(await manager.RoleExistsAsync(role.Name));
            UnitTestHelper.IsSuccess(await manager.CreateAsync(role));
            Assert.True(await manager.RoleExistsAsync(role.Name));
        }

        [Fact]
        public async Task BadValidatorBlocksCreateTest()
        {
            var manager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>());
            manager.RoleValidator = new AlwaysBadValidator<IdentityRole>();
            UnitTestHelper.IsFailure(await manager.CreateAsync(new IdentityRole("blocked")),
                AlwaysBadValidator<IdentityRole>.ErrorMessage);
        }

        [Fact]
        public async Task BadValidatorBlocksAllUpdatesTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var manager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(db));
            var role = new IdentityRole("poorguy");
            UnitTestHelper.IsSuccess(await manager.CreateAsync(role));
            var error = AlwaysBadValidator<IdentityRole>.ErrorMessage;
            manager.RoleValidator = new AlwaysBadValidator<IdentityRole>();
            UnitTestHelper.IsFailure(await manager.UpdateAsync(role), error);
        }

        [Fact]
        public async Task DeleteRoleTest()
        {
            var manager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(UnitTestHelper.CreateDefaultDb()));
            var role = new IdentityRole("delete");
            Assert.False(await manager.RoleExistsAsync(role.Name));
            UnitTestHelper.IsSuccess(await manager.CreateAsync(role));
            UnitTestHelper.IsSuccess(await manager.DeleteAsync(role));
            Assert.False(await manager.RoleExistsAsync(role.Name));
        }

        [Fact]
        public void DeleteRoleSyncTest()
        {
            var manager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(UnitTestHelper.CreateDefaultDb()));
            var role = new IdentityRole("delete");
            Assert.False(manager.RoleExists(role.Name));
            UnitTestHelper.IsSuccess(manager.Create(role));
            UnitTestHelper.IsSuccess(manager.Delete(role));
            Assert.False(manager.RoleExists(role.Name));
        }

        [Fact]
        public void DeleteFailWithUnknownRoleTest()
        {
            var manager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(UnitTestHelper.CreateDefaultDb()));
            Assert.Throws<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.DeleteAsync(new IdentityRole("bogus"))));
        }

        [Fact]
        public async Task RoleFindByIdTest()
        {
            var manager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(UnitTestHelper.CreateDefaultDb()));
            var role = new IdentityRole("FindById");
            Assert.Null(await manager.FindByIdAsync(role.Id));
            UnitTestHelper.IsSuccess(await manager.CreateAsync(role));
            Assert.Equal(role, await manager.FindByIdAsync(role.Id));
        }

        [Fact]
        public void RoleFindByIdSyncTest()
        {
            var manager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(UnitTestHelper.CreateDefaultDb()));
            var role = new IdentityRole("FindById");
            Assert.Null(manager.FindById(role.Id));
            UnitTestHelper.IsSuccess(manager.Create(role));
            Assert.Equal(role, manager.FindById(role.Id));
        }

        [Fact]
        public async Task RoleFindByNameTest()
        {
            var manager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(UnitTestHelper.CreateDefaultDb()));
            var role = new IdentityRole("FindByName");
            Assert.Null(await manager.FindByNameAsync(role.Name));
            Assert.False(await manager.RoleExistsAsync(role.Name));
            UnitTestHelper.IsSuccess(await manager.CreateAsync(role));
            Assert.Equal(role, await manager.FindByNameAsync(role.Name));
        }

        [Fact]
        public void RoleFindByNameSyncTest()
        {
            var manager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(UnitTestHelper.CreateDefaultDb()));
            var role = new IdentityRole("FindByName");
            Assert.False(manager.RoleExists(role.Name));
            UnitTestHelper.IsSuccess(manager.Create(role));
            Assert.Equal(role, manager.FindByName(role.Name));
        }

        [Fact]
        public async Task UpdateRoleNameTest()
        {
            var manager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(UnitTestHelper.CreateDefaultDb()));
            var role = new IdentityRole("update");
            Assert.False(await manager.RoleExistsAsync(role.Name));
            UnitTestHelper.IsSuccess(await manager.CreateAsync(role));
            Assert.True(await manager.RoleExistsAsync(role.Name));
            role.Name = "Changed";
            UnitTestHelper.IsSuccess(await manager.UpdateAsync(role));
            Assert.False(await manager.RoleExistsAsync("update"));
            Assert.Equal(role, await manager.FindByNameAsync(role.Name));
        }

        [Fact]
        public void UpdateRoleNameSyncTest()
        {
            var manager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(UnitTestHelper.CreateDefaultDb()));
            var role = new IdentityRole("update");
            Assert.False(manager.RoleExists(role.Name));
            UnitTestHelper.IsSuccess(manager.Create(role));
            Assert.True(manager.RoleExists(role.Name));
            role.Name = "Changed";
            UnitTestHelper.IsSuccess(manager.Update(role));
            Assert.False(manager.RoleExists("update"));
            Assert.Equal(role, manager.FindByName(role.Name));
        }

        [Fact]
        public async Task QuerableRolesTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var manager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(db));
            //string[] users = { "u1", "u2", "u3", "u4" };
            IdentityRole[] roles =
            {
                new IdentityRole("r1"), new IdentityRole("r2"), new IdentityRole("r3"),
                new IdentityRole("r4")
            };
            //foreach (var u in users) {
            //    UnitTestHelper.IsSuccess(await store.CreateAsync(u, "password"));
            //}
            foreach (IdentityRole r in roles)
            {
                UnitTestHelper.IsSuccess(await manager.CreateAsync(r));
                //foreach (var u in users) {
                //    UnitTestHelper.IsSuccess(await store.Roles.AddUserToRoleAsync(u, r.Name));
                //    Assert.True(await store.Roles.IsUserInRoleAsync(u, r.Name));
                //}
            }
            Assert.Equal(roles.Length, manager.Roles.Count());
            var r1 = manager.Roles.FirstOrDefault(r => r.Name == "r1");
            Assert.Equal(roles[0], r1);
        }

        [Fact]
        public async Task DeleteRoleNonEmptySucceedsTest()
        {
            // Need fail if not empty?
            var db = UnitTestHelper.CreateDefaultDb();
            var userMgr = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            var roleMgr = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(db));
            var role = new IdentityRole("deleteNonEmpty");
            Assert.False(await roleMgr.RoleExistsAsync(role.Name));
            UnitTestHelper.IsSuccess(await roleMgr.CreateAsync(role));
            var user = new IdentityUser("t");
            UnitTestHelper.IsSuccess(await userMgr.CreateAsync(user));
            UnitTestHelper.IsSuccess(await userMgr.AddToRoleAsync(user.Id, role.Name));
            UnitTestHelper.IsSuccess(await roleMgr.DeleteAsync(role));
            Assert.False(await roleMgr.RoleExistsAsync(role.Name));
            // REVIEW: We should throw if deleteing a non empty role?
            var roles = await userMgr.GetRolesAsync(user.Id);
            Assert.Equal(0, roles.Count());
        }

        [Fact]
        public async Task DeleteUserRemovesFromRoleTest()
        {
            // Need fail if not empty?
            var db = UnitTestHelper.CreateDefaultDb();
            var userMgr = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            var roleMgr = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(db));
            var role = new IdentityRole("deleteNonEmpty");
            Assert.False(await roleMgr.RoleExistsAsync(role.Name));
            UnitTestHelper.IsSuccess(await roleMgr.CreateAsync(role));
            var user = new IdentityUser("t");
            UnitTestHelper.IsSuccess(await userMgr.CreateAsync(user));
            UnitTestHelper.IsSuccess(await userMgr.AddToRoleAsync(user.Id, role.Name));
            UnitTestHelper.IsSuccess(await userMgr.DeleteAsync(user));
            role = roleMgr.FindById(role.Id);
            Assert.Equal(0, role.Users.Count());
        }

        [Fact]
        public async Task DeleteRoleUnknownFailsTest()
        {
            var manager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(UnitTestHelper.CreateDefaultDb()));
            var role = new IdentityRole("bogus");
            Assert.False(await manager.RoleExistsAsync(role.Name));
            Assert.Throws<InvalidOperationException>(() => AsyncHelper.RunSync(() => manager.DeleteAsync(role)));
        }

        [Fact]
        public async Task CreateRoleFailsIfExistsTest()
        {
            var manager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(UnitTestHelper.CreateDefaultDb()));
            var role = new IdentityRole("dupeRole");
            Assert.False(await manager.RoleExistsAsync(role.Name));
            UnitTestHelper.IsSuccess(await manager.CreateAsync(role));
            Assert.True(await manager.RoleExistsAsync(role.Name));
            var role2 = new IdentityRole("dupeRole");
            UnitTestHelper.IsFailure(await manager.CreateAsync(role2));
        }

        [Fact]
        public async Task CreateDuplicateRoleAtStoreFailsTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var store = new RoleStore<IdentityRole>(db);
            var role = new IdentityRole("dupeRole");
            await store.CreateAsync(role);
            db.SaveChanges();
            var role2 = new IdentityRole("dupeRole");
            Assert.Throws<DbEntityValidationException>(() => AsyncHelper.RunSync(() => store.CreateAsync(role2)));
        }

        [Fact]
        public async Task AddUserToRoleTest()
        {
            var manager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(UnitTestHelper.CreateDefaultDb()));
            var roleManager =
                new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(UnitTestHelper.CreateDefaultDb()));
            var role = new IdentityRole("addUserTest");
            UnitTestHelper.IsSuccess(await roleManager.CreateAsync(role));
            IdentityUser[] users =
            {
                new IdentityUser("1"), new IdentityUser("2"), new IdentityUser("3"),
                new IdentityUser("4")
            };
            foreach (IdentityUser u in users)
            {
                UnitTestHelper.IsSuccess(await manager.CreateAsync(u));
                UnitTestHelper.IsSuccess(await manager.AddToRoleAsync(u.Id, role.Name));
                Assert.Equal(1, u.Roles.Count(ur => ur.RoleId == role.Id));
                Assert.True(await manager.IsInRoleAsync(u.Id, role.Name));
            }
        }

        [Fact]
        public async Task GetRolesForUserTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var userManager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            var roleManager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(db));
            IdentityUser[] users =
            {
                new IdentityUser("u1"), new IdentityUser("u2"), new IdentityUser("u3"),
                new IdentityUser("u4")
            };
            IdentityRole[] roles =
            {
                new IdentityRole("r1"), new IdentityRole("r2"), new IdentityRole("r3"),
                new IdentityRole("r4")
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
                Assert.Equal(users.Length, r.Users.Count());
            }

            foreach (var u in users)
            {
                var rs = await userManager.GetRolesAsync(u.Id);
                Assert.Equal(roles.Length, rs.Count);
                foreach (IdentityRole r in roles)
                {
                    Assert.True(rs.Any(role => role == r.Name));
                }
            }
        }

        [Fact]
        public void GetRolesForUserSyncTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var userManager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            var roleManager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(db));
            IdentityUser[] users =
            {
                new IdentityUser("u1"), new IdentityUser("u2"), new IdentityUser("u3"),
                new IdentityUser("u4")
            };
            IdentityRole[] roles =
            {
                new IdentityRole("r1"), new IdentityRole("r2"), new IdentityRole("r3"),
                new IdentityRole("r4")
            };
            foreach (var u in users)
            {
                UnitTestHelper.IsSuccess(userManager.Create(u));
            }
            foreach (var r in roles)
            {
                UnitTestHelper.IsSuccess(roleManager.Create(r));
                foreach (var u in users)
                {
                    UnitTestHelper.IsSuccess(userManager.AddToRole(u.Id, r.Name));
                    Assert.True(userManager.IsInRole(u.Id, r.Name));
                }
            }

            foreach (var u in users)
            {
                var rs = userManager.GetRoles(u.Id);
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
            var db = UnitTestHelper.CreateDefaultDb();
            var userManager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            var roleManager =
                new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(UnitTestHelper.CreateDefaultDb()));
            var user = new IdentityUser("MultiRoleUser");
            UnitTestHelper.IsSuccess(await userManager.CreateAsync(user));
            IdentityRole[] roles =
            {
                new IdentityRole("r1"), new IdentityRole("r2"), new IdentityRole("r3"),
                new IdentityRole("r4")
            };
            foreach (var r in roles)
            {
                UnitTestHelper.IsSuccess(await roleManager.CreateAsync(r));
                UnitTestHelper.IsSuccess(await userManager.AddToRoleAsync(user.Id, r.Name));
                Assert.Equal(1, user.Roles.Count(ur => ur.RoleId == r.Id));
                Assert.True(await userManager.IsInRoleAsync(user.Id, r.Name));
            }
            UnitTestHelper.IsSuccess(await userManager.RemoveFromRoleAsync(user.Id, roles[2].Name));
            Assert.Equal(0, user.Roles.Count(ur => ur.RoleId == roles[2].Id));
            Assert.False(await userManager.IsInRoleAsync(user.Id, roles[2].Name));
        }

        [Fact]
        public async Task RemoveUserFromRoleTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var userManager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            var roleManager =
                new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(UnitTestHelper.CreateDefaultDb()));
            IdentityUser[] users =
            {
                new IdentityUser("1"), new IdentityUser("2"), new IdentityUser("3"),
                new IdentityUser("4")
            };
            foreach (var u in users)
            {
                UnitTestHelper.IsSuccess(await userManager.CreateAsync(u, "password"));
            }
            var r = new IdentityRole("r1");
            UnitTestHelper.IsSuccess(await roleManager.CreateAsync(r));
            foreach (var u in users)
            {
                UnitTestHelper.IsSuccess(await userManager.AddToRoleAsync(u.Id, r.Name));
                Assert.True(await userManager.IsInRoleAsync(u.Id, r.Name));
            }
            foreach (var u in users)
            {
                UnitTestHelper.IsSuccess(await userManager.RemoveFromRoleAsync(u.Id, r.Name));
                Assert.Equal(0, u.Roles.Count(ur => ur.RoleId == r.Id));
                Assert.False(await userManager.IsInRoleAsync(u.Id, r.Name));
            }
            Assert.Equal(0, db.Set<IdentityUserRole>().Count());
        }

        [Fact]
        public void RemoveUserFromRoleSyncTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var store = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            var roleManager =
                new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(UnitTestHelper.CreateDefaultDb()));
            IdentityUser[] users =
            {
                new IdentityUser("1"), new IdentityUser("2"), new IdentityUser("3"),
                new IdentityUser("4")
            };
            foreach (var u in users)
            {
                UnitTestHelper.IsSuccess(store.Create(u, "password"));
            }
            var r = new IdentityRole("r1");
            UnitTestHelper.IsSuccess(roleManager.Create(r));
            foreach (var u in users)
            {
                UnitTestHelper.IsSuccess(store.AddToRole(u.Id, r.Name));
                Assert.True(store.IsInRole(u.Id, r.Name));
            }
            foreach (var u in users)
            {
                UnitTestHelper.IsSuccess(store.RemoveFromRole(u.Id, r.Name));
                Assert.False(store.IsInRole(u.Id, r.Name));
            }
            Assert.Equal(0, db.Set<IdentityUserRole>().Count());
        }

        [Fact]
        public async Task RemoveUserFromBogusRolesFails()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var userManager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            var user = new IdentityUser("1");
            UnitTestHelper.IsSuccess(await userManager.CreateAsync(user));
            UnitTestHelper.IsFailure(await userManager.RemoveFromRolesAsync(user.Id, "bogus"), "User is not in role.");
        }

        [Fact]
        public async Task AddToBogusRolesFails()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var userManager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            var user = new IdentityUser("1");
            UnitTestHelper.IsSuccess(await userManager.CreateAsync(user));
            Assert.Throws<InvalidOperationException>(() => userManager.AddToRoles(user.Id, "bogus"));
        }

        [Fact]
        public async Task AddToDupeRolesFails()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var userManager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            var user = new IdentityUser("1");
            var roleManager =
                new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(UnitTestHelper.CreateDefaultDb()));
            IdentityRole[] roles =
            {
                new IdentityRole("r1"), new IdentityRole("r2"), new IdentityRole("r3"),
                new IdentityRole("r4")
            };
            foreach (var r in roles)
            {
                UnitTestHelper.IsSuccess(await roleManager.CreateAsync(r));
            }
            UnitTestHelper.IsSuccess(await userManager.CreateAsync(user));
            UnitTestHelper.IsSuccess(await userManager.AddToRolesAsync(user.Id, "r1", "r2", "r3", "r4"));
            UnitTestHelper.IsFailure(await userManager.AddToRolesAsync(user.Id, "r1", "r2", "r3", "r4"), "User already in role.");
        }

        [Fact]
        public async Task RemoveUserFromRolesTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var userManager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            var roleManager =
                new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(UnitTestHelper.CreateDefaultDb()));
            var user = new IdentityUser("1");
            IdentityRole[] roles =
            {
                new IdentityRole("r1"), new IdentityRole("r2"), new IdentityRole("r3"),
                new IdentityRole("r4")
            };
            foreach (var r in roles)
            {
                UnitTestHelper.IsSuccess(await roleManager.CreateAsync(r));
            }
            UnitTestHelper.IsSuccess(await userManager.CreateAsync(user));
            UnitTestHelper.IsSuccess(await userManager.AddToRolesAsync(user.Id, roles.Select(ro => ro.Name).ToArray()));
            Assert.Equal(roles.Count(), db.Set<IdentityUserRole>().Count());
            Assert.True(await userManager.IsInRoleAsync(user.Id, "r1"));
            Assert.True(await userManager.IsInRoleAsync(user.Id, "r2"));
            Assert.True(await userManager.IsInRoleAsync(user.Id, "r3"));
            Assert.True(await userManager.IsInRoleAsync(user.Id, "r4"));
            var rs = await userManager.GetRolesAsync(user.Id);
            UnitTestHelper.IsSuccess(await userManager.RemoveFromRolesAsync(user.Id, "r1", "r3"));
            rs = await userManager.GetRolesAsync(user.Id);
            Assert.False(await userManager.IsInRoleAsync(user.Id, "r1"));
            Assert.False(await userManager.IsInRoleAsync(user.Id, "r3"));
            Assert.True(await userManager.IsInRoleAsync(user.Id, "r2"));
            Assert.True(await userManager.IsInRoleAsync(user.Id, "r4"));
            UnitTestHelper.IsSuccess(await userManager.RemoveFromRolesAsync(user.Id, "r2", "r4"));
            Assert.False(await userManager.IsInRoleAsync(user.Id, "r2"));
            Assert.False(await userManager.IsInRoleAsync(user.Id, "r4"));
            Assert.Equal(0, db.Set<IdentityUserRole>().Count());
        }

        [Fact]
        public void RemoveUserFromRolesSync()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var userManager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            var roleManager =
                new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(UnitTestHelper.CreateDefaultDb()));
            var user = new IdentityUser("1");
            IdentityRole[] roles =
            {
                new IdentityRole("r1"), new IdentityRole("r2"), new IdentityRole("r3"),
                new IdentityRole("r4")
            };
            foreach (var r in roles)
            {
                UnitTestHelper.IsSuccess(roleManager.Create(r));
            }
            UnitTestHelper.IsSuccess(userManager.Create(user));
            UnitTestHelper.IsSuccess(userManager.AddToRoles(user.Id, roles.Select(ro => ro.Name).ToArray()));
            Assert.Equal(roles.Count(), db.Set<IdentityUserRole>().Count());
            Assert.True(userManager.IsInRole(user.Id, "r1"));
            Assert.True(userManager.IsInRole(user.Id, "r2"));
            Assert.True(userManager.IsInRole(user.Id, "r3"));
            Assert.True(userManager.IsInRole(user.Id, "r4"));
            var rs = userManager.GetRoles(user.Id);
            UnitTestHelper.IsSuccess(userManager.RemoveFromRoles(user.Id, "r1", "r3"));
            rs = userManager.GetRoles(user.Id);
            Assert.False(userManager.IsInRole(user.Id, "r1"));
            Assert.False(userManager.IsInRole(user.Id, "r3"));
            Assert.True(userManager.IsInRole(user.Id, "r2"));
            Assert.True(userManager.IsInRole(user.Id, "r4"));
            UnitTestHelper.IsSuccess(userManager.RemoveFromRoles(user.Id, "r2", "r4"));
            Assert.False(userManager.IsInRole(user.Id, "r2"));
            Assert.False(userManager.IsInRole(user.Id, "r4"));
            Assert.Equal(0, db.Set<IdentityUserRole>().Count());
        }

//        [Fact]
//        public async Task UnknownUserThrowsTest() {
//            var manager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(UnitTestHelper.CreateDefaultDb()));
//            var r = new IdentityRole("r1");
//            UnitTestHelper.IsSuccess(await manager.Roles.CreateAsync(r));
//            ExceptionHelper.ExpectException<InvalidOperationException>(() => AsyncHelper.RunSync(() => manager.Roles.RemoveUserFromRoleAsync("whatever", r.Name)));
//            ExceptionHelper.ExpectException<InvalidOperationException>(() => AsyncHelper.RunSync(() => manager.Roles.AddUserToRoleAsync("whatever", r.Name)));
//            ExceptionHelper.ExpectException<InvalidOperationException>(() => AsyncHelper.RunSync(() => manager.Roles.GetRolesForUserAsync("whatever")));
//        }

        [Fact]
        public async Task UnknownRoleThrowsTest()
        {
            var manager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(UnitTestHelper.CreateDefaultDb()));
            var u = new IdentityUser("u1");
            UnitTestHelper.IsSuccess(await manager.CreateAsync(u));
            Assert.Throws<InvalidOperationException>(
                () => AsyncHelper.RunSync(() => manager.AddToRoleAsync(u.Id, "bogus")));
            // CONSIDER: should these other methods also throw if role doesn't exist?
            //ExceptionHelper.ExpectException<InvalidOperationException>(() => AsyncHelper.RunSync(() => manager.RemoveFromRoleAsync(u.Id, "bogus")));
            //ExceptionHelper.ExpectException<InvalidOperationException>(() => AsyncHelper.RunSync(() => manager.IsInRoleAsync(u.Id, "whatever")));
        }

        [Fact]
        public async Task RemoveUserNotInRoleFailsTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var userMgr = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            var roleMgr = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(db));
            var role = new IdentityRole("addUserDupeTest");
            var user = new IdentityUser("user1");
            UnitTestHelper.IsSuccess(await userMgr.CreateAsync(user));
            UnitTestHelper.IsSuccess(await roleMgr.CreateAsync(role));
            var result = await userMgr.RemoveFromRoleAsync(user.Id, role.Name);
            UnitTestHelper.IsFailure(result, "User is not in role.");
        }

        [Fact]
        public async Task AddUserToRoleFailsIfAlreadyInRoleTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var userMgr = new UserManager<IdentityUser>(new UserStore<IdentityUser>(db));
            var roleMgr = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(db));
            var role = new IdentityRole("addUserDupeTest");
            var user = new IdentityUser("user1");
            UnitTestHelper.IsSuccess(await userMgr.CreateAsync(user));
            UnitTestHelper.IsSuccess(await roleMgr.CreateAsync(role));
            UnitTestHelper.IsSuccess(await userMgr.AddToRoleAsync(user.Id, role.Name));
            Assert.True(await userMgr.IsInRoleAsync(user.Id, role.Name));
            UnitTestHelper.IsFailure(await userMgr.AddToRoleAsync(user.Id, role.Name), "User already in role.");
        }

        [Fact]
        public async Task FindRoleByNameWithManagerTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var roleMgr = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(db));
            var role = new IdentityRole("findRoleByNameTest");
            UnitTestHelper.IsSuccess(await roleMgr.CreateAsync(role));
            Assert.Equal(role.Id, (await roleMgr.FindByNameAsync(role.Name)).Id);
        }

        [Fact]
        public async Task FindRoleWithManagerTest()
        {
            var db = UnitTestHelper.CreateDefaultDb();
            var roleMgr = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(db));
            var role = new IdentityRole("findRoleTest");
            UnitTestHelper.IsSuccess(await roleMgr.CreateAsync(role));
            Assert.Equal(role.Name, (await roleMgr.FindByIdAsync(role.Id)).Name);
        }

        public class NoopRoleStore : IRoleStore<IdentityRole>
        {
            public Task CreateAsync(IdentityRole role)
            {
                throw new NotImplementedException();
            }

            public Task UpdateAsync(IdentityRole role)
            {
                throw new NotImplementedException();
            }

            public Task DeleteAsync(IdentityRole role)
            {
                throw new NotImplementedException();
            }

            public Task<IdentityRole> FindByIdAsync(string roleId)
            {
                throw new NotImplementedException();
            }

            public Task<IdentityRole> FindByNameAsync(string roleName)
            {
                throw new NotImplementedException();
            }

            public void Dispose()
            {
            }
        }
    }
}