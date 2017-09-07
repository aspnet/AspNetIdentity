// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using Xunit;

namespace Identity.Test
{
    public static class ExceptionHelper
    {
        public static TException ThrowsWithError<TException>(Assert.ThrowsDelegate act, string error)
            where TException : Exception
        {
            var e = Assert.Throws<TException>(act);
            if (e != null)
            {
                Assert.Equal(error, e.Message);
            }
            return e;
        }

        public static ArgumentException ThrowsArgumentException(Assert.ThrowsDelegate del, string exceptionMessage,
            string paramName)
        {
            var e = Assert.Throws<ArgumentException>(del);
            // Only check exception message on English build and OS, since some exception messages come from the OS
            // and will be in the native language.
            if (UnitTestHelper.EnglishBuildAndOS)
            {
                Assert.Equal(exceptionMessage, e.Message); //, "Incorrect exception message.");
                Assert.Equal(paramName, e.ParamName); //, "Incorrect exception parameter name.");
            }
            return e;
        }

        public static ArgumentException ThrowsArgumentNullOrEmpty(Assert.ThrowsDelegate del, string paramName)
        {
            return ThrowsArgumentException(del, "Value cannot be null or empty.\r\nParameter name: " + paramName,
                paramName);
        }

        public static ArgumentNullException ThrowsArgumentNull(Assert.ThrowsDelegate del, string paramName)
        {
            var e = Assert.Throws<ArgumentNullException>(del);
            Assert.Equal(paramName, e.ParamName);
            return e;
        }
    }
}