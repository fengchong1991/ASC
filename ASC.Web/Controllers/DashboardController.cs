using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using ASC.Web.Configuration;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace ASC.Web.Controllers
{
    public class DashboardController : BaseController
    {
        private IOptions<ApplicationSettings> _settings;
        public DashboardController(IOptions<ApplicationSettings> settings)
        {
            _settings = settings;
        }

        public IActionResult Dashboard()
        {
            return View();
        }
    }
}