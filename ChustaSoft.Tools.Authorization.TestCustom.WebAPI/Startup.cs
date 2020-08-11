﻿using ChustaSoft.Tools.Authorization.AspNet;
using ChustaSoft.Tools.Authorization.TestCustom.WebAPI;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Data.SqlClient;


namespace ChustaSoft.Tools.Authorization
{
    public class Startup
    {

        #region Constants

        private const string CONNECTIONSTRING_NAME = "AuthorizationConnection";

        #endregion


        #region Fields


        private readonly IConfiguration _configuration;

        #endregion

        
        #region Constructor

        public Startup(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        #endregion


        #region Public methods

        public void ConfigureServices(IServiceCollection services)
        {
            services.RegisterAuthorization<CustomUser, CustomRole>(_configuration, "d5ab5e3f5799445fb9f68d1fcdda3b9f")
                .WithUserCreatedAction<CustomUser, CustomUserAction>()
                .WithSqlServerProvider<AuthCustomContext, CustomUser, CustomRole>(BuildConnectionString());

            services.AddMvc()
                .AddAuthorizationControllers();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, IServiceProvider serviceProvider)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .AddEnvironmentVariables();

            if (env.EnvironmentName.Equals("dev"))
            {
                app.UseDeveloperExceptionPage();
                builder.AddUserSecrets<Startup>();
            }

            app.ConfigureAuthorization(env, serviceProvider)
                .SetupDatabase<AuthCustomContext, CustomUser, CustomRole>()
                .DefaultUsers(ub =>
                {
                    ub.Add("SYSTEM", "Sys.1234");
                    ub.Add("ADMIN", "Admn.1234").WithRole("Admin");
                });
        }

        #endregion


        #region Private methods

        private string BuildConnectionString()
        {
            var builder = new SqlConnectionStringBuilder(_configuration.GetConnectionString(CONNECTIONSTRING_NAME));

            return builder.ConnectionString;
        }

        #endregion

    }
}
