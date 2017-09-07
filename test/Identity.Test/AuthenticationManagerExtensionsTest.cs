// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Moq;
using Xunit;

namespace Identity.Test
{
    public class AuthenticationManagerExtensionsTest
    {
        [Fact]
        public void ExtensionsNullCheckTest()
        {
            IAuthenticationManager manager = null;
            ExceptionHelper.ThrowsArgumentNull(() => manager.GetExternalAuthenticationTypes(), "manager");
            ExceptionHelper.ThrowsArgumentNull(
                () => AsyncHelper.RunSync(() => manager.GetExternalIdentityAsync("whatever")), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => AsyncHelper.RunSync(() => manager.GetExternalLoginInfoAsync()),
                "manager");
            ExceptionHelper.ThrowsArgumentNull(
                () => AsyncHelper.RunSync(() => manager.GetExternalLoginInfoAsync("key", "blah")), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.GetExternalLoginInfo(), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.GetExternalLoginInfo("key", "blah"), "manager");
            ExceptionHelper.ThrowsArgumentNull(() => manager.CreateTwoFactorRememberBrowserIdentity("foo"), "manager");
            ExceptionHelper.ThrowsArgumentNull(
                () => AsyncHelper.RunSync(() => manager.TwoFactorBrowserRememberedAsync("foo")), "manager");
        }

        [Fact]
        public async Task GetExternalLoginReturnsNullIfNoNameIdentifierTest()
        {
            var manager = new Mock<IAuthenticationManager>();
            manager.Setup(a => a.AuthenticateAsync(DefaultAuthenticationTypes.ExternalCookie))
                .Returns(
                    Task.FromResult(new AuthenticateResult(CreateNoNameIdentifierIdentity("name", "authtype"),
                        new AuthenticationProperties(), new AuthenticationDescription())));
            Assert.Null(await manager.Object.GetExternalLoginInfoAsync());
        }

        [Fact]
        public async Task GetExternalLoginDoesNotBlowUpWithNullName()
        {
            var manager = new Mock<IAuthenticationManager>();
            var identity = new ClaimsIdentity(DefaultAuthenticationTypes.ExternalCookie);
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, "foo"));
            manager.Setup(a => a.AuthenticateAsync(DefaultAuthenticationTypes.ExternalCookie))
                .Returns(
                    Task.FromResult(new AuthenticateResult(identity,
                        new AuthenticationProperties(), new AuthenticationDescription())));
            var externalInfo = await manager.Object.GetExternalLoginInfoAsync();
            Assert.NotNull(externalInfo);
        }

        [Fact]
        public async Task GetExternalLoginReturnsNullIfNoExternalIdTest()
        {
            var manager = new Mock<IAuthenticationManager>();
            manager.Setup(a => a.AuthenticateAsync(DefaultAuthenticationTypes.ExternalCookie))
                .Returns(Task.FromResult<AuthenticateResult>(null));
            Assert.Null(await manager.Object.GetExternalLoginInfoAsync());
        }

        [Fact]
        public async Task GetExternalLoginWithXsrfReturnsNullIfNoNameIdentifierTest()
        {
            var manager = new Mock<IAuthenticationManager>();
            manager.Setup(a => a.AuthenticateAsync(DefaultAuthenticationTypes.ExternalCookie))
                .Returns(
                    Task.FromResult(new AuthenticateResult(CreateNoNameIdentifierIdentity("name", "authtype"),
                        new AuthenticationProperties(), new AuthenticationDescription())));
            Assert.Null(await manager.Object.GetExternalLoginInfoAsync("xsrfKey", "foo"));
        }

        [Fact]
        public async Task GetExternalLoginWithXsrfReturnsNullIfNoClaimsIdentityTest()
        {
            var manager = new Mock<IAuthenticationManager>();
            manager.Setup(a => a.AuthenticateAsync(DefaultAuthenticationTypes.ExternalCookie))
                .Returns(
                    Task.FromResult(new AuthenticateResult(null, new AuthenticationProperties(),
                        new AuthenticationDescription())));
            Assert.Null(await manager.Object.GetExternalLoginInfoAsync("xsrfKey", "foo"));
        }

        [Fact]
        public async Task GetExternalLoginTest()
        {
            var mockManager = new Mock<IAuthenticationManager>();
            var props = new AuthenticationProperties();
            var loginInfo = new ExternalLoginInfo
            {
                Login = new UserLoginInfo("loginProvider", "key"),
                DefaultUserName = "Hao Kung"
            };
            var identity = CreateIdentity(loginInfo);
            mockManager.Setup(a => a.AuthenticateAsync(DefaultAuthenticationTypes.ExternalCookie))
                .Returns(Task.FromResult(new AuthenticateResult(identity, props, new AuthenticationDescription())));
            var manager = mockManager.Object;
            var externalInfo = await manager.GetExternalLoginInfoAsync();
            Assert.NotNull(externalInfo);
            Assert.Equal(identity, externalInfo.ExternalIdentity);
            Assert.Equal(loginInfo.Login.LoginProvider, externalInfo.Login.LoginProvider);
            Assert.Equal(loginInfo.Login.ProviderKey, externalInfo.Login.ProviderKey);
            Assert.Equal("HaoKung", externalInfo.DefaultUserName);
        }

        [Fact]
        public void GetExternalLoginSyncTest()
        {
            var mockManager = new Mock<IAuthenticationManager>();
            var props = new AuthenticationProperties();
            var loginInfo = new ExternalLoginInfo
            {
                Login = new UserLoginInfo("loginProvider", "key"),
                DefaultUserName = "Hao Kung"
            };
            mockManager.Setup(a => a.AuthenticateAsync(DefaultAuthenticationTypes.ExternalCookie))
                .Returns(
                    Task.FromResult(new AuthenticateResult(CreateIdentity(loginInfo), props,
                        new AuthenticationDescription())));
            var manager = mockManager.Object;
            var externalInfo = manager.GetExternalLoginInfo();
            Assert.NotNull(externalInfo);
            Assert.Equal(loginInfo.Login.LoginProvider, externalInfo.Login.LoginProvider);
            Assert.Equal(loginInfo.Login.ProviderKey, externalInfo.Login.ProviderKey);
            Assert.Equal("HaoKung", externalInfo.DefaultUserName);
        }

        [Fact]
        public async Task GetExternalLoginWithXsrfTest()
        {
            var mockManager = new Mock<IAuthenticationManager>();
            var props = new AuthenticationProperties();
            props.Dictionary["xsrfKey"] = "Hao";
            var loginInfo = new ExternalLoginInfo
            {
                Login = new UserLoginInfo("loginProvider", "key"),
                DefaultUserName = "Hao Kung"
            };
            mockManager.Setup(a => a.AuthenticateAsync(DefaultAuthenticationTypes.ExternalCookie))
                .Returns(
                    Task.FromResult(new AuthenticateResult(CreateIdentity(loginInfo), props,
                        new AuthenticationDescription())));
            var manager = mockManager.Object;
            var externalInfo = await manager.GetExternalLoginInfoAsync("xsrfKey", "Hao");
            Assert.NotNull(externalInfo);
            Assert.Equal(loginInfo.Login.LoginProvider, externalInfo.Login.LoginProvider);
            Assert.Equal(loginInfo.Login.ProviderKey, externalInfo.Login.ProviderKey);
            Assert.Equal("HaoKung", externalInfo.DefaultUserName);
        }

        [Fact]
        public void GetExternalLoginWithXsrfSyncTest()
        {
            var mockManager = new Mock<IAuthenticationManager>();
            var props = new AuthenticationProperties();
            props.Dictionary["xsrfKey"] = "Hao";
            var loginInfo = new ExternalLoginInfo
            {
                Login = new UserLoginInfo("loginProvider", "key"),
                DefaultUserName = "Hao Kung"
            };
            mockManager.Setup(a => a.AuthenticateAsync(DefaultAuthenticationTypes.ExternalCookie))
                .Returns(
                    Task.FromResult(new AuthenticateResult(CreateIdentity(loginInfo), props,
                        new AuthenticationDescription())));
            var manager = mockManager.Object;
            var externalInfo = manager.GetExternalLoginInfo("xsrfKey", "Hao");
            Assert.NotNull(externalInfo);
            Assert.Equal(loginInfo.Login.LoginProvider, externalInfo.Login.LoginProvider);
            Assert.Equal(loginInfo.Login.ProviderKey, externalInfo.Login.ProviderKey);
            Assert.Equal("HaoKung", externalInfo.DefaultUserName);
        }

        [Fact]
        public async Task GetExternalLoginNullIfXsrfFailsTest()
        {
            var mockManager = new Mock<IAuthenticationManager>();
            var props = new AuthenticationProperties();
            props.Dictionary["xsrfKey"] = "Hao";
            var loginInfo = new ExternalLoginInfo
            {
                Login = new UserLoginInfo("loginProvider", "key"),
                DefaultUserName = "Hao Kung"
            };
            mockManager.Setup(a => a.AuthenticateAsync(DefaultAuthenticationTypes.ExternalCookie))
                .Returns(
                    Task.FromResult(new AuthenticateResult(CreateIdentity(loginInfo), props,
                        new AuthenticationDescription())));
            var manager = mockManager.Object;
            var externalInfo = await manager.GetExternalLoginInfoAsync("xsrfKey", "NotHao");
            Assert.Null(externalInfo);
        }

        [Fact]
        public void GetExternalLoginNullIfXsrfFailsSyncTest()
        {
            var mockManager = new Mock<IAuthenticationManager>();
            var props = new AuthenticationProperties();
            props.Dictionary["xsrfKey"] = "Hao";
            var loginInfo = new ExternalLoginInfo
            {
                Login = new UserLoginInfo("loginProvider", "key"),
                DefaultUserName = "Hao Kung"
            };
            mockManager.Setup(a => a.AuthenticateAsync(DefaultAuthenticationTypes.ExternalCookie))
                .Returns(
                    Task.FromResult(new AuthenticateResult(CreateIdentity(loginInfo), props,
                        new AuthenticationDescription())));
            var manager = mockManager.Object;
            var externalInfo = manager.GetExternalLoginInfo("xsrfKey", "NotHao");
            Assert.Null(externalInfo);
        }

        [Fact]
        public async Task GetExternalIdentityReturnsNullIfNoNameIdentifierTest()
        {
            var manager = new Mock<IAuthenticationManager>();
            manager.Setup(a => a.AuthenticateAsync(DefaultAuthenticationTypes.ExternalCookie))
                .Returns(
                    Task.FromResult(new AuthenticateResult(CreateNoNameIdentifierIdentity("name", "authtype"),
                        new AuthenticationProperties(), new AuthenticationDescription())));
            Assert.Null(await manager.Object.GetExternalIdentityAsync(DefaultAuthenticationTypes.ExternalCookie));
        }

        [Fact]
        public async Task GetExternalIdentityReturnsNullIfNullNameTest()
        {
            var manager = new Mock<IAuthenticationManager>();
            manager.Setup(a => a.AuthenticateAsync(DefaultAuthenticationTypes.ExternalCookie))
                .Returns(
                    Task.FromResult(new AuthenticateResult(CreateNoClaimIdentity("authtype"),
                        new AuthenticationProperties(), new AuthenticationDescription())));
            Assert.Null(await manager.Object.GetExternalIdentityAsync(DefaultAuthenticationTypes.ExternalCookie));
        }

        [Fact]
        public async Task GetExternalIdentityTest()
        {
            var mockManager = new Mock<IAuthenticationManager>();
            var props = new AuthenticationProperties();
            var loginInfo = new ExternalLoginInfo
            {
                Login = new UserLoginInfo("loginProvider", "key"),
                DefaultUserName = "Hao Kung"
            };
            mockManager.Setup(a => a.AuthenticateAsync(DefaultAuthenticationTypes.ExternalCookie))
                .Returns(
                    Task.FromResult(new AuthenticateResult(CreateIdentity(loginInfo), props,
                        new AuthenticationDescription())));
            var manager = mockManager.Object;
            var id = await manager.GetExternalIdentityAsync(DefaultAuthenticationTypes.ExternalCookie);
            Assert.NotNull(id);
            var idClaim = id.FindFirst(ClaimTypes.NameIdentifier);
            Assert.NotNull(idClaim);
            Assert.Equal(loginInfo.Login.LoginProvider, idClaim.Issuer);
            Assert.Equal(loginInfo.Login.ProviderKey, idClaim.Value);
            Assert.Equal(loginInfo.DefaultUserName, id.Name);
        }

        [Fact]
        public void CreateRememberBrowserIdentityTest()
        {
            var mockManager = new Mock<IAuthenticationManager>();
            var manager = mockManager.Object;
            var identity = manager.CreateTwoFactorRememberBrowserIdentity("userId");
            Assert.NotNull(identity);
            Assert.Equal("userId", identity.GetUserId());
            Assert.Equal(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie, identity.AuthenticationType);
        }

        [Fact]
        public async Task BrowserRemeberedTest()
        {
            var mockManager = new Mock<IAuthenticationManager>();
            var manager = mockManager.Object;
            var props = new AuthenticationProperties();
            var identity = manager.CreateTwoFactorRememberBrowserIdentity("userId");
            mockManager.Setup(a => a.AuthenticateAsync(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie))
                .Returns(Task.FromResult(new AuthenticateResult(identity, props, new AuthenticationDescription())));
            Assert.True(await manager.TwoFactorBrowserRememberedAsync("userId"));
            Assert.False(await manager.TwoFactorBrowserRememberedAsync("userNotId"));
        }

        [Fact]
        public async Task BrowserRemeberedFailWithNoIdentityTest()
        {
            var mockManager = new Mock<IAuthenticationManager>();
            var manager = mockManager.Object;
            var props = new AuthenticationProperties();
            mockManager.Setup(a => a.AuthenticateAsync(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie))
                .Returns(Task.FromResult(new AuthenticateResult(null, props, new AuthenticationDescription())));
            Assert.False(await manager.TwoFactorBrowserRememberedAsync("userId"));
        }

        [Fact]
        public async Task BrowserRemeberedFailWithWrongIdentityTest()
        {
            var mockManager = new Mock<IAuthenticationManager>();
            var manager = mockManager.Object;
            var props = new AuthenticationProperties();
            mockManager.Setup(a => a.AuthenticateAsync(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie))
                .Returns(
                    Task.FromResult(new AuthenticateResult(new ClaimsIdentity("whatever"), props,
                        new AuthenticationDescription())));
            Assert.False(await manager.TwoFactorBrowserRememberedAsync("userId"));
        }


        public static ClaimsIdentity CreateNoNameIdentifierIdentity(string name, string authenticationType)
        {
            return new ClaimsIdentity(
                new[]
                {
                    new Claim(ClaimTypes.Name, name)
                },
                authenticationType);
        }

        public static ClaimsIdentity CreateNoClaimIdentity(string authenticationType)
        {
            return new ClaimsIdentity(
                new Claim[] {},
                authenticationType);
        }

        public static ClaimsIdentity CreateIdentity(ExternalLoginInfo info)
        {
            return new ClaimsIdentity(
                new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, info.Login.ProviderKey, null, info.Login.LoginProvider),
                    new Claim(ClaimTypes.Name, info.DefaultUserName)
                },
                info.Login.LoginProvider);
        }
    }
}