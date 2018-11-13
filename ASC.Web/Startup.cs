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
using ASC.DataAccess.Interfaces;
using ASC.DataAccess;
using System.Reflection;
using System.Linq;
using ASC.Business.Interfaces;
using ASC.Business;
using AutoMapper;
using Newtonsoft.Json.Serialization;

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

            services.AddAuthentication().AddGoogle(g =>
            {
                g.ClientId = Configuration["Google:Identity:ClientId"];
                g.ClientSecret = Configuration["Google:Identity:ClientSecret"];
            });

            // Add application services.
            services.AddTransient<IEmailSender, EmailSender>();
            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
            services.AddScoped<IUnitOfWork>(p => new UnitOfWork(Configuration.GetSection("ConnectionStrings:DefaultConnection").Value));
            services.AddScoped<IMasterDataOperations, MasterDataOperations>();
            services.AddScoped<IMasterDataCacheOperations, MasterDataCacheOperations>();

            services.AddAutoMapper();
            services.AddOptions();
            services.Configure<ApplicationSettings>(Configuration.GetSection("AppSettings"));
            services.AddSession();
            services.AddMvc().AddJsonOptions(o => o.SerializerSettings.ContractResolver = new DefaultContractResolver());
            services.AddDistributedRedisCache(options =>
                {
                    options.Configuration = Configuration.GetSection("CacheSettings:CacheConnectionString").Value;
                    options.InstanceName = Configuration.GetSection("CacheSettings:CacheInstance").Value;
                });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public async void Configure(IApplicationBuilder app, IHostingEnvironment env, IUnitOfWork unitOfWork, IMasterDataCacheOperations masterDataCacheOperations)
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
            app.UseSession();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });

            var models = Assembly.Load(new AssemblyName("ASC.Models")).GetTypes().Where(type => type.Namespace == "ASC.Models.Models");

            foreach(var model in models)
            {
                var repository = Activator.CreateInstance(typeof(Repository<>).MakeGenericType(model), unitOfWork);
                MethodInfo method = typeof(Repository<>).MakeGenericType(model).GetMethod("CreateTableAsync");
                method.Invoke(repository, null);
            }

            await masterDataCacheOperations.CreateMasterDataCache();
        }
    }
}
