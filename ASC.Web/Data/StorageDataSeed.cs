using ASC.Models.BaseTypes;
using ASC.Web.Configuration;
using ElCamino.AspNetCore.Identity.AzureTable.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ASC.Web.Data
{
    public interface IIdentitySeed
    {
        Task Seed(UserManager<ApplicationUser> userManager, RoleManager<ElCamino.AspNetCore.Identity.AzureTable.Model.IdentityRole> roleManager, IOptions<ApplicationSettings> options);
    }

    public class IdentitySeed : IIdentitySeed
    {
        public async Task Seed(UserManager<ApplicationUser> userManager, RoleManager<ElCamino.AspNetCore.Identity.AzureTable.Model.IdentityRole> roleManager, IOptions<ApplicationSettings> options)
        {
            // Get roles
            var roles = options.Value.Roles.Split(',');

            foreach(var role in roles)
            {
                if (!await roleManager.RoleExistsAsync(role))
                {
                    ElCamino.AspNetCore.Identity.AzureTable.Model.IdentityRole newRole = new ElCamino.AspNetCore.Identity.AzureTable.Model.IdentityRole
                    {
                        Name = role
                    };

                    IdentityResult roleResult = await roleManager.CreateAsync(newRole);
                }
            }

            // Create Admin if not existed
            // Create admin if he doesn’t exist
            var admin = await userManager.FindByEmailAsync(options.Value.AdminEmail);
            if (admin == null)
            {
                ApplicationUser user = new ApplicationUser
                {
                    UserName = options.Value.AdminName,
                    Email = options.Value.AdminEmail,
                    EmailConfirmed = true
                };

                IdentityResult result = await userManager.CreateAsync(user, options.Value.AdminPassword);
                await userManager.AddClaimAsync(user, new System.Security.Claims.Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", options.Value.AdminEmail));
                await userManager.AddClaimAsync(user, new System.Security.Claims.Claim("IsActive", "True"));

                // Add Admin to Admin roles
                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(user, Roles.Admin.ToString());
                }
            }

            // Create a service engineer
            var engineer = await userManager.FindByEmailAsync(options.Value.EngineerEmail);
            if (engineer == null)
            {
                ApplicationUser user = new ApplicationUser
                {
                    UserName = options.Value.EngineerName,
                    Email = options.Value.EngineerEmail,
                    EmailConfirmed = true,
                    LockoutEnabled = false
                };

                IdentityResult result = await userManager.CreateAsync(user, options.Value.EngineerPassword);
                var result2 = await userManager.AddClaimAsync(user, new System.Security.Claims.Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", options.Value.EngineerEmail));
                var result3 = await userManager.AddClaimAsync(user, new System.Security.Claims.Claim("IsActive", "True"));
                // Add Service Engineer to Engineer role
                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(user, Roles.Engineer.ToString());
                }
            }
        }
    }
}
