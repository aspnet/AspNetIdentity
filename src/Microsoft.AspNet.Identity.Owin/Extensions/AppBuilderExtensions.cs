// Copyright (c) Microsoft Corporation, Inc. All rights reserved.
// Licensed under the MIT License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.OAuth;

namespace Owin
{
    /// <summary>
    ///     Extensions off of IAppBuilder to make it easier to configure the SignInCookies
    /// </summary>
    public static class AppBuilderExtensions
    {
        private const string CookiePrefix = ".AspNet.";

        /// <summary>
        ///     Registers a callback that will be invoked to create an instance of type T that will be stored in the OwinContext
        ///     which can fetched via context.Get
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="app">The <see cref="IAppBuilder" /> passed to the configuration method</param>
        /// <param name="createCallback">Invoked to create an instance of T</param>
        /// <returns>The updated <see cref="IAppBuilder" /></returns>
        public static IAppBuilder CreatePerOwinContext<T>(this IAppBuilder app, Func<T> createCallback)
            where T : class, IDisposable
        {
            return CreatePerOwinContext<T>(app, (options, context) => createCallback());
        }

        /// <summary>
        ///     Registers a callback that will be invoked to create an instance of type T that will be stored in the OwinContext
        ///     which can fetched via context.Get
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="app"></param>
        /// <param name="createCallback"></param>
        /// <returns></returns>
        public static IAppBuilder CreatePerOwinContext<T>(this IAppBuilder app,
            Func<IdentityFactoryOptions<T>, IOwinContext, T> createCallback) where T : class, IDisposable
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            return app.CreatePerOwinContext(createCallback, (options, instance) => instance.Dispose());
        }

        /// <summary>
        ///     Registers a callback that will be invoked to create an instance of type T that will be stored in the OwinContext
        ///     which can fetched via context.Get
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="app"></param>
        /// <param name="createCallback"></param>
        /// <param name="disposeCallback"></param>
        /// <returns></returns>
        public static IAppBuilder CreatePerOwinContext<T>(this IAppBuilder app,
            Func<IdentityFactoryOptions<T>, IOwinContext, T> createCallback,
            Action<IdentityFactoryOptions<T>, T> disposeCallback) where T : class, IDisposable
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (createCallback == null)
            {
                throw new ArgumentNullException("createCallback");
            }
            if (disposeCallback == null)
            {
                throw new ArgumentNullException("disposeCallback");
            }

            app.Use(typeof (IdentityFactoryMiddleware<T, IdentityFactoryOptions<T>>),
                new IdentityFactoryOptions<T>
                {
                    DataProtectionProvider = app.GetDataProtectionProvider(),
                    Provider = new IdentityFactoryProvider<T>
                    {
                        OnCreate = createCallback,
                        OnDispose = disposeCallback
                    }
                });
            return app;
        }

        /// <summary>
        ///     Configure the app to use owin middleware based cookie authentication for external identities
        /// </summary>
        /// <param name="app"></param>
        public static void UseExternalSignInCookie(this IAppBuilder app)
        {
            UseExternalSignInCookie(app, DefaultAuthenticationTypes.ExternalCookie);
        }

        /// <summary>
        ///     Configure the app to use owin middleware based cookie authentication for external identities
        /// </summary>
        /// <param name="app"></param>
        /// <param name="externalAuthenticationType"></param>
        public static void UseExternalSignInCookie(this IAppBuilder app, string externalAuthenticationType)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }

            app.SetDefaultSignInAsAuthenticationType(externalAuthenticationType);
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = externalAuthenticationType,
                AuthenticationMode = AuthenticationMode.Passive,
                CookieName = CookiePrefix + externalAuthenticationType,
                ExpireTimeSpan = TimeSpan.FromMinutes(5),
            });
        }

        /// <summary>
        ///     Configures a cookie intended to be used to store the partial credentials for two factor authentication
        /// </summary>
        /// <param name="app"></param>
        /// <param name="authenticationType"></param>
        /// <param name="expires"></param>
        public static void UseTwoFactorSignInCookie(this IAppBuilder app, string authenticationType, TimeSpan expires)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = authenticationType,
                AuthenticationMode = AuthenticationMode.Passive,
                CookieName = CookiePrefix + authenticationType,
                ExpireTimeSpan = expires,
            });
        }

        /// <summary>
        ///     Configures a cookie intended to be used to store whether two factor authentication has been done already
        /// </summary>
        /// <param name="app"></param>
        /// <param name="authenticationType"></param>
        public static void UseTwoFactorRememberBrowserCookie(this IAppBuilder app, string authenticationType)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = authenticationType,
                AuthenticationMode = AuthenticationMode.Passive,
                CookieName = CookiePrefix + authenticationType,
            });
        }

        /// <summary>
        ///     Configure the app to use owin middleware based oauth bearer tokens
        /// </summary>
        /// <param name="app"></param>
        /// <param name="options"></param>
        [SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "Auth",
            Justification = "By Design")]
        public static void UseOAuthBearerTokens(this IAppBuilder app, OAuthAuthorizationServerOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.UseOAuthAuthorizationServer(options);

            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions
            {
                AccessTokenFormat = options.AccessTokenFormat,
                AccessTokenProvider = options.AccessTokenProvider,
                AuthenticationMode = options.AuthenticationMode,
                AuthenticationType = options.AuthenticationType,
                Description = options.Description,
                Provider = new ApplicationOAuthBearerProvider(),
                SystemClock = options.SystemClock
            });

            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions
            {
                AccessTokenFormat = options.AccessTokenFormat,
                AccessTokenProvider = options.AccessTokenProvider,
                AuthenticationMode = AuthenticationMode.Passive,
                AuthenticationType = DefaultAuthenticationTypes.ExternalBearer,
                Description = options.Description,
                Provider = new ExternalOAuthBearerProvider(),
                SystemClock = options.SystemClock
            });
        }

        private class ApplicationOAuthBearerProvider : OAuthBearerAuthenticationProvider
        {
            public override Task ValidateIdentity(OAuthValidateIdentityContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException("context");
                }
                if (context.Ticket.Identity.Claims.Any(c => c.Issuer != ClaimsIdentity.DefaultIssuer))
                {
                    context.Rejected();
                }
                return Task.FromResult<object>(null);
            }
        }

        private class ExternalOAuthBearerProvider : OAuthBearerAuthenticationProvider
        {
            public override Task ValidateIdentity(OAuthValidateIdentityContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException("context");
                }
                if (context.Ticket.Identity.Claims.Count() == 0)
                {
                    context.Rejected();
                }
                else if (context.Ticket.Identity.Claims.All(c => c.Issuer == ClaimsIdentity.DefaultIssuer))
                {
                    context.Rejected();
                }

                return Task.FromResult<object>(null);
            }
        }
    }
}