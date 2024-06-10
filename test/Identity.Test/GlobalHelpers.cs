using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

#if NETFRAMEWORK
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.DataProtection;
#else
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.AspNetCore;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
#endif

namespace Identity.Test
{
    public static class GlobalHelpers
    {
#if NETFRAMEWORK
        public static OwinContext CreateContext()
        {
            return new OwinContext();
        }

        public static CookieValidateIdentityContext CreateCookieValidateIdentityContext(IOwinContext owinContext, AuthenticationTicket ticket, CookieAuthenticationOptions cookieAuthenticationOptions)
        {
            return new CookieValidateIdentityContext(owinContext, ticket, new CookieAuthenticationOptions());
        }

        public static AuthenticationTicket CreateAuthenticationTicket(ClaimsIdentity id, AuthenticationProperties authenticationProperties)
        {
            return new AuthenticationTicket(id, authenticationProperties);
        }

        public static AuthenticateResult CreateAuthenticateResult(ClaimsIdentity identity, AuthenticationProperties properties)
        {
            return new AuthenticateResult(identity, properties, new AuthenticationDescription());
        }

        public static IDictionary<string, string> GetPropertiesDictionary(this AuthenticationProperties props)
        {
            return props.Dictionary;
        }

        public static ClaimsIdentity ExtractClaimsIdentity(this CookieValidateIdentityContext context)
        {
            return context.Identity;
        }

        public static IDataProtectionProvider CreateDataProtectionProvider()
        {
            return new DpapiDataProtectionProvider();
        }
#else
        public static DefaultHttpContext CreateContext()
        {
            var services = new ServiceCollection();
            services.AddAuthentication(DefaultAuthenticationTypes.ExternalCookie)
                .AddCookie(DefaultAuthenticationTypes.ExternalCookie)
                .AddCookie(DefaultAuthenticationTypes.TwoFactorCookie);
            services.AddLogging();

            return new DefaultHttpContext()
            {
                RequestServices = services.BuildServiceProvider()
            };
        }

        public static CookieValidatePrincipalContext CreateCookieValidateIdentityContext(DefaultHttpContext owinContext, AuthenticationTicket ticket, CookieAuthenticationOptions cookieAuthenticationOptions)
        {
            return new CookieValidatePrincipalContext(owinContext, new AuthenticationScheme(ticket.AuthenticationScheme, null, typeof(CookieAuthenticationHandler)), new CookieAuthenticationOptions(), ticket);
        }

        public static AuthenticationTicket CreateAuthenticationTicket(ClaimsIdentity id, AuthenticationProperties authenticationProperties)
        {
            return new AuthenticationTicket(new ClaimsPrincipal(id), authenticationProperties, id.AuthenticationType);
        }

        public static AuthenticateResult CreateAuthenticateResult(ClaimsIdentity identity, AuthenticationProperties properties)
        {
            return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), properties, identity.AuthenticationType));
        }

        public static IDictionary<string, object> GetPropertiesDictionary(this AuthenticationProperties props)
        {
            return props.Parameters;
        }

        public static ClaimsIdentity? ExtractClaimsIdentity(this CookieValidatePrincipalContext context)
        {
            return context.Principal?.Identity as ClaimsIdentity;
        }

        public static IDataProtector Create(this IDataProtectionProvider provider, string purpose, params string[] subPurpose)
        {
            return provider.CreateProtector(purpose, subPurpose);
        }

        public static IDataProtectionProvider CreateDataProtectionProvider()
        {
            return new EphemeralDataProtectionProvider();
        }
#endif
    }
}