using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using ASC.Web.Data;
using Microsoft.Extensions.Options;
using ASC.Web.Configuration;
using Microsoft.AspNetCore.Authorization;
using ASC.Web.Models.AccountViewModels;
using ASC.Utilities;
using ASC.Web.Services;
using ASC.Models.BaseTypes;

namespace ASC.Web.Controllers
{
    [Route("[controller]/[action]")]
    public class AccountController : BaseController
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IEmailSender _emailSender;
        private readonly ILogger _logger;
        private readonly IOptions<ApplicationSettings> _settings;

        public AccountController(
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            IEmailSender emailSender,
            ILogger<AccountController> logger,
            IOptions<ApplicationSettings> settings)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _emailSender = emailSender;
            _logger = logger;
            _settings = settings; 
        }
                
        [AllowAnonymous]
        public async Task<IActionResult> Login(string returnUrl = null)
        {
            await _signInManager.SignOutAsync();
            ViewData["ReturnUrl"] = returnUrl;

            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    return View(model);
                }

                var isActive = Boolean.Parse(user.Claims.SingleOrDefault(p => p.ClaimType == "IsActive").ClaimValue);
                if (!isActive)
                {
                    ModelState.AddModelError(string.Empty, "Account has been locked.");
                    return View(model);
                }

                var result = await _signInManager.PasswordSignInAsync(user.UserName, model.Password, model.RememberMe, lockoutOnFailure: false);
                if (result.Succeeded)
                {
                    _logger.LogInformation(1, "User logged in.");
                    if (!String.IsNullOrWhiteSpace(returnUrl))
                        return Redirect(returnUrl);
                    else
                        return RedirectToAction("Dashboard", "Dashboard");
                }

                //if (result.RequiresTwoFactor)
                //{
                //    return RedirectToAction(nameof(SendCode), new
                //    {
                //        ReturnUrl = returnUrl,
                //        RememberMe = model.RememberMe
                //    });
                //}

                if (result.IsLockedOut)
                {
                    _logger.LogWarning(2, "User account locked out.");
                    return View("Lockout");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    return View(model);
                }
            }

            return View(model);
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            //_logger.LogInformation("User logged out.");
            return RedirectToAction("Index", "Home");
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> InitiateResetPassword()
        {
            // Find user
            var userEmail = HttpContext.User.GetCurrentUserDetails().Email;
            var user = await _userManager.FindByEmailAsync(userEmail);

            // Generate user code
            var code = await _userManager.GeneratePasswordResetTokenAsync(user);
            var callBackUrl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code = code }, protocol: HttpContext.Request.Scheme);

            // Send email
            await _emailSender.SendEmailAsync(userEmail, "Reset Passowrd", $"Please reset your password by clicking here: <a href='{callBackUrl}'>link</a>");

            return View("ResetPasswordEmailConfirmation");
        }

        [AllowAnonymous]
        public IActionResult ResetPassword(string code = null)
        {
            return code == null ? View("Error") : View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _userManager.FindByEmailAsync(model.Email);

            if(user == null)
            {
                return RedirectToAction(nameof(AccountController.ResetPasswordConfirmation), "Account");
            }

            var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);

            if (result.Succeeded)
            {
                if (HttpContext.User.Identity.IsAuthenticated)
                    await _signInManager.SignOutAsync();
                return RedirectToAction(nameof(AccountController.ResetPasswordConfirmation),
                "Account");
            }

            AddErrors(result);
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                if(user == null || !(await _userManager.IsEmailConfirmedAsync(user)))
                {
                    return View("ResetPasswordEmailConfirmation");
                }

                var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                var callbackUrl = Url.Action(nameof(ResetPassword), "Account", new { userId = user.Id, code = code }, protocol: HttpContext.Request.Scheme);

                await _emailSender.SendEmailAsync(model.Email, "Reset Password", $"Please reset your password by clicking here: <a href='{callbackUrl}'>link</a>");

                return View("ResetPasswordEmailConfirmation");
            }

            return View(model);
        }

        public async Task<IActionResult> ServiceEngineers()
        {
            var serviceEngineers = await _userManager.GetUsersInRoleAsync(Roles.Engineer.ToString());

            // Hold all service engineers in session
            HttpContext.Session.SetSession("ServiceEngineers", serviceEngineers);
            return View(new ServiceEngineerViewModel()
            {
                ServiceEngineers = serviceEngineers?.ToList(),
                Registration = new ServiceEngineerRegistrationViewModel() { IsEdit = false }
            });
        }



        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }
    }
}
