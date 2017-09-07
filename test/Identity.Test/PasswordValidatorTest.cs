// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Xunit;

namespace Identity.Test
{
    public class PasswordValidatorTest
    {
        [Fact]
        public async Task RequiredLengthTest()
        {
            var error = "Passwords must be at least 6 characters.";
            var valid = new PasswordValidator {RequiredLength = 6};
            UnitTestHelper.IsFailure(await valid.ValidateAsync(""), error);
            UnitTestHelper.IsFailure(await valid.ValidateAsync("abcde"), error);
            UnitTestHelper.IsSuccess(await valid.ValidateAsync("abcdef"));
            UnitTestHelper.IsSuccess(await valid.ValidateAsync("abcdeldkajfd"));
        }

        [Fact]
        public async Task RequiredNonAlphanumericTest()
        {
            var error = "Passwords must have at least one non letter or digit character.";
            var valid = new PasswordValidator {RequireNonLetterOrDigit = true};
            UnitTestHelper.IsFailure(await valid.ValidateAsync("abcde"), error);
            UnitTestHelper.IsSuccess(await valid.ValidateAsync("abcd@e!ld!kajfd"));
            UnitTestHelper.IsSuccess(await valid.ValidateAsync("!!!!!!"));
        }

        [Fact]
        public async Task MixedRequiredTest()
        {
            var alphaError = "Passwords must have at least one non letter or digit character.";
            var upperError = "Passwords must have at least one uppercase ('A'-'Z').";
            var lowerError = "Passwords must have at least one lowercase ('a'-'z').";
            var digitError = "Passwords must have at least one digit ('0'-'9').";
            var lengthError = "Passwords must be at least 6 characters.";
            var valid = new PasswordValidator
            {
                RequireNonLetterOrDigit = true,
                RequireDigit = true,
                RequireLowercase = true,
                RequireUppercase = true,
                RequiredLength = 6
            };
            UnitTestHelper.IsFailure(await valid.ValidateAsync("abcde"),
                string.Join(" ", lengthError, alphaError, digitError, upperError));
            UnitTestHelper.IsFailure(await valid.ValidateAsync("a@B@cd"), digitError);
            UnitTestHelper.IsFailure(await valid.ValidateAsync("___"),
                string.Join(" ", lengthError, digitError, lowerError, upperError));
            UnitTestHelper.IsFailure(await valid.ValidateAsync("a_b9de"), upperError);
            UnitTestHelper.IsSuccess(await valid.ValidateAsync("abcd@e!ld!kaj9Fd"));
        }
    }
}