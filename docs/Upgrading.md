# Upgrading Impostor

Sometimes we make incompatible changes to existing code. This document lists these changes and which changes you should make as a server administrator.

## Impostor 1.10.9

Impostor now targets .NET 10 instead of .NET 8. As a result you should change your server as follows:

- Install the [.NET 10.0 runtime](https://dotnet.microsoft.com/download/dotnet/10.0) (ASP.NET Core Runtime or SDK) on the machine that runs the server. .NET 8 is no longer used and reaches end of support on November 10, 2026.
- If you have plugins, they need to be rebuilt against `net10.0`, since `Impostor.Api` targets .NET 10 as well. Check those plugins for an update before upgrading the server.

## Impostor 1.9.0

Previously we recommended using the Impostor.Http plugin for HTTP matchmaking. Because Among Us now relies on HTTP matchmaking, this plugin is now part of the default installation. As a result, you should change your server as follows:

- If you have Impostor.Http installed, you should remove that plugin. If you have changed the default settings, you need to move these changes to the [HttpServer section in config.json](Server-configuration.md#HttpServer).
- If you have plugins that required Impostor.Http's API (like Reactor.Impostor.Http), you should check that plugin for updates
- It is no longer necessary to add the ASP.NET Core folder to the PluginLoader's LibraryPaths

