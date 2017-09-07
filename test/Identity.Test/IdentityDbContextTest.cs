// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System.Data.Entity;
using System.Data.Entity.Validation;
using System.Data.SqlClient;
using System.Linq;
using Microsoft.AspNet.Identity.EntityFramework;
using Xunit;

namespace Identity.Test
{
    public class IdentityDbContextTest
    {
        [Fact]
        public void EnsureDefaultSchema()
        {
            VerifyDefaultSchema(CreateDb());
        }

        internal static void VerifyDefaultSchema(DbContext dbContext)
        {
            var sqlConn = dbContext.Database.Connection as SqlConnection;
            // Give up and assume its ok if its not a sql connection
            if (sqlConn == null)
            {
                Assert.True(false, "Expected a sql connection");
            }
            using (var db = new SqlConnection(sqlConn.ConnectionString))
            {
                db.Open();
                Assert.True(VerifyColumns(db, "AspNetUsers", "Id", "UserName", "Email", "PasswordHash", "SecurityStamp",
                    "EmailConfirmed", "PhoneNumber", "PhoneNumberConfirmed", "TwoFactorEnabled", "LockoutEnabled",
                    "LockoutEndDateUtc", "AccessFailedCount"));
                Assert.True(VerifyColumns(db, "AspNetRoles", "Id", "Name"));
                Assert.True(VerifyColumns(db, "AspNetUserRoles", "UserId", "RoleId"));
                Assert.True(VerifyColumns(db, "AspNetUserClaims", "Id", "UserId", "ClaimType", "ClaimValue"));
                Assert.True(VerifyColumns(db, "AspNetUserLogins", "UserId", "ProviderKey", "LoginProvider"));

                VerifyIndex(db, "AspNetRoles", "RoleNameIndex");
                VerifyIndex(db, "AspNetUsers", "UserNameIndex");
                db.Close();
            }
        }

        internal static bool VerifyColumns(SqlConnection conn, string table, params string[] columns)
        {
            var count = 0;
            using (
                var command =
                    new SqlCommand("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS where TABLE_NAME=@Table", conn))
            {
                command.Parameters.Add(new SqlParameter("Table", table));
                using (var reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        count++;
                        if (!columns.Contains(reader.GetString(0)))
                        {
                            return false;
                        }
                    }
                    return count == columns.Length;
                }
            }
        }

        internal static void VerifyIndex(SqlConnection conn, string table, string index)
        {
            using (
                var command =
                    new SqlCommand(
                        "SELECT COUNT(*) FROM sys.indexes where NAME=@Index AND object_id = OBJECT_ID(@Table)", conn))
            {
                command.Parameters.Add(new SqlParameter("Index", index));
                command.Parameters.Add(new SqlParameter("Table", table));
                using (var reader = command.ExecuteReader())
                {
                    Assert.True(reader.Read());
                    Assert.True(reader.GetInt32(0) > 0);
                }
            }
        }

        [Fact]
        public void IdentityDbContextEnsuresUserNamesUniqueTest()
        {
            var db = CreateDb();
            db.Users.Add(new IdentityUser("Hao"));
            db.SaveChanges();
            db.Users.Add(new IdentityUser("HaO"));
            try
            {
                db.SaveChanges();
                Assert.False(true);
            }
            catch (DbEntityValidationException e)
            {
                Assert.Equal("User name HaO is already taken.",
                    e.EntityValidationErrors.First().ValidationErrors.First().ErrorMessage);
            }
        }

        [Fact]
        public void IdentityDbContextEnsuresRoleNamesUniqueTest()
        {
            var db = CreateDb();
            db.Roles.Add(new IdentityRole("admin"));
            db.SaveChanges();
            db.Roles.Add(new IdentityRole("ADMIN"));
            try
            {
                db.SaveChanges();
                Assert.False(true);
            }
            catch (DbEntityValidationException e)
            {
                Assert.Equal("Role ADMIN already exists.",
                    e.EntityValidationErrors.First().ValidationErrors.First().ErrorMessage);
            }
        }

        private IdentityDbContext CreateDb()
        {
            Database.SetInitializer(new DropCreateDatabaseAlways<IdentityDbContext>());
            var db = new IdentityDbContext();
            db.Database.Initialize(true);
            return db;
        }
    }
}