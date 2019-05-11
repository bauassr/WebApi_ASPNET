using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using Microsoft.Owin.Security.OAuth;
using System.Security.Claims;

namespace WebApplication1
{
    public class AppAuthorization : OAuthAuthorizationServerProvider
    {

        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {

            context.Validated(); // Client is validation 
        }

        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {

            var idententy = new ClaimsIdentity(context.Options.AuthenticationType);

            if(context.UserName =="admin"&& context.Password=="admin")
            {
                idententy.AddClaim(new Claim(ClaimTypes.Role, "admin"));
                idententy.AddClaim(new Claim("username", "admin "));
                idententy.AddClaim(new Claim(ClaimTypes.Name, "Shivam Singh"));
                context.Validated(idententy);
            }
            else if (context.UserName == "user" && context.Password == "user")
            {
                idententy.AddClaim(new Claim(ClaimTypes.Role, "user"));
                idententy.AddClaim(new Claim("username", "user"));
                idententy.AddClaim(new Claim(ClaimTypes.Name, "Shivam Singh1"));
                context.Validated(idententy);
            }
            else
            {
                context.SetError("Invalid_grant", "Provided username and password is incorrect");
                return;
            }
        }

    }
}