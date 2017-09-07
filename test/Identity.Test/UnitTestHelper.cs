// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Data.Entity;
using System.Data.Entity.SqlServer;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Xunit;

namespace Identity.Test
{
    public static class UnitTestHelper
    {
        public static bool EnglishBuildAndOS
        {
            get
            {
                var englishBuild = String.Equals(CultureInfo.CurrentUICulture.TwoLetterISOLanguageName, "en",
                    StringComparison.OrdinalIgnoreCase);
                var englishOS = String.Equals(CultureInfo.CurrentCulture.TwoLetterISOLanguageName, "en",
                    StringComparison.OrdinalIgnoreCase);
                return englishBuild && englishOS;
            }
        }

        public static IdentityDbContext CreateDefaultDb()
        {
            Database.SetInitializer(new DropCreateDatabaseAlways<IdentityDbContext>());
            var db = new IdentityDbContext();
            db.Database.Initialize(true);
            var foo = typeof (SqlProviderServices);
            return db;
        }

        public static void IsSuccess(IdentityResult result)
        {
            Assert.NotNull(result);
            Assert.True(result.Succeeded);
        }

        public static void IsFailure(IdentityResult result)
        {
            Assert.NotNull(result);
            Assert.False(result.Succeeded);
        }

        public static void IsFailure(IdentityResult result, string error)
        {
            Assert.NotNull(result);
            Assert.False(result.Succeeded);
            Assert.Equal(error, result.Errors.First());
        }
    }

    public class AlwaysBadValidator<T> : IIdentityValidator<T>
    {
        public const string ErrorMessage = "I'm Bad.";

        public Task<IdentityResult> ValidateAsync(T item)
        {
            return Task.FromResult(IdentityResult.Failed(ErrorMessage));
        }
    }

    public class NoopValidator<T> : IIdentityValidator<T>
    {
        public Task<IdentityResult> ValidateAsync(T item)
        {
            return Task.FromResult(IdentityResult.Success);
        }
    }
}