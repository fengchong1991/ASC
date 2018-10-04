using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using ASC.Utilities;
using ASC.Web.Configuration;
using ASC.Web.Data;
using ElCamino.AspNetCore.Identity.AzureTable.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace ASC.Web.Controllers
{
    public class HomeController : AnonymousController
    {

        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IOptions<ApplicationSettings> _settings;
        private readonly RoleManager<ElCamino.AspNetCore.Identity.AzureTable.Model.IdentityRole> _roleManager;

        public HomeController(
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            IOptions<ApplicationSettings> settings,
            RoleManager<ElCamino.AspNetCore.Identity.AzureTable.Model.IdentityRole> roleManager)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _settings = settings;
            _roleManager = roleManager;
        }


        public IActionResult Index()
        {
            ViewBag.Title = _settings.Value.ApplicationTitle;

            return View();
        }

        public async Task<IActionResult> SeedDbAsync()
        {
            IdentitySeed seed = new IdentitySeed();

            await seed.Seed(_userManager, _roleManager, _settings);

            return null;
        }
    }
}