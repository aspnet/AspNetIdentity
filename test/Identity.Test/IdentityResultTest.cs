// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System.Linq;
using Microsoft.AspNet.Identity;
using Xunit;

namespace Identity.Test
{
    public class IdentityResultTest
    {
        [Fact]
        public void NullErrorsBecomeDefaultTest()
        {
            var result = new IdentityResult(null);
            Assert.NotNull(result.Errors);
            Assert.False(result.Succeeded);
            Assert.Equal(1, result.Errors.Count());
            Assert.Equal("An unknown failure has occured.", result.Errors.First());
        }
    }
}