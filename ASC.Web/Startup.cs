using System;
using Microsoft.AspNetCore.Builder;
using ElCamino.AspNetCore.Identity.AzureTable.Model;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using ASC.Web.Data;
using ASC.Web.Services;
using ASC.Web.Configuration;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace ASC.Web
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            //services.AddDbContext<ApplicationDbContext>(options =>
            //    options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection")));

            // Add Elcamino Azure Table Identity services.

            services.AddIdentity<ApplicationUser, ElCamino.AspNetCore.Identity.AzureTable.Model.IdentityRole>((options) =>
            {
                options.User.RequireUniqueEmail = true;
            })
            //or use .AddAzureTableStores with your ApplicationUser extends IdentityUser if your code depends on the Role, Claim and Token collections on the user object.
            //You can safely switch between .AddAzureTableStores and .AddAzureTableStoresV2. Just make sure the Application User extends the correct IdentityUser/IdentityUserV2
                .AddAzureTableStores<ApplicationDbContext>(new Func<IdentityConfiguration>(() =>
                {
                    IdentityConfiguration idconfig = new IdentityConfiguration();
                    idconfig.TablePrefix = Configuration.GetSection("IdentityAzureTable:IdentityConfiguration:TablePrefix").Value;
                    idconfig.StorageConnectionString = Configuration.GetSection("IdentityAzureTable:IdentityConfiguration:StorageConnectionString").Value;
                    idconfig.LocationMode = Configuration.GetSection("IdentityAzureTable:IdentityConfiguration:LocationMode").Value;
                    return idconfig;
                }))
                .AddDefaultTokenProviders()
                .CreateAzureTablesIfNotExists<ApplicationDbContext>(); //can remove after first run;
            
            // Add application services.
            services.AddTransient<IEmailSender, EmailSender>();
            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

            services.AddOptions();
            services.Configure<ApplicationSettings>(Configuration.GetSection("AppSettings"));
            services.AddMvc();

        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseBrowserLink();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();

            app.UseAuthentication();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
