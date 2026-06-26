using System.Threading.Tasks;
using Impostor.Api.Plugins;
using Microsoft.Extensions.Logging;

namespace Impostor.Plugins.Admin;

[ImpostorPlugin("ume.impostor.admin")]
public class AdminPlugin : PluginBase
{
    private readonly ILogger<AdminPlugin> _logger;

    public AdminPlugin(ILogger<AdminPlugin> logger)
    {
        _logger = logger;
    }

    public override ValueTask EnableAsync()
    {
        _logger.LogInformation("Admin panel plugin enabled. Access /admin in your browser.");
        return default;
    }

    public override ValueTask DisableAsync()
    {
        _logger.LogInformation("Admin panel plugin disabled.");
        return default;
    }
}
