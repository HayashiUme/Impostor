using System.Reflection;
using Impostor.Api.Plugins;
using Impostor.Plugins.Admin.Http;
using Impostor.Plugins.Admin.Stores;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Impostor.Plugins.Admin;

public class AdminPluginStartup : IPluginHttpStartup
{
    public void ConfigureHost(IHostBuilder host)
    {
    }

    public void ConfigureServices(IServiceCollection services)
    {
        services.AddSingleton<BanStore>();
    }

    public void ConfigureWebApplication(IApplicationBuilder builder)
    {
        var partManager = builder.ApplicationServices.GetRequiredService<ApplicationPartManager>();
        partManager.ApplicationParts.Add(new AssemblyPart(typeof(AdminController).Assembly));
    }
}
