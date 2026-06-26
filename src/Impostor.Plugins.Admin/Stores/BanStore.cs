using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Json;

#nullable enable

namespace Impostor.Plugins.Admin.Stores;

public class BanStore
{
    private readonly string _filePath;
    private readonly object _lock = new();
    private List<BanEntry> _ipBans = new();
    private bool _loaded;

    public BanStore()
    {
        var dir = Path.Combine(Directory.GetCurrentDirectory(), "Admin");
        Directory.CreateDirectory(dir);
        _filePath = Path.Combine(dir, "bans.json");
    }

    public BanEntry BanIp(IPAddress ip, string reason)
    {
        EnsureLoaded();

        var ipStr = NormalizeIp(ip);
        lock (_lock)
        {
            // Remove any existing ban for this IP
            _ipBans.RemoveAll(b => b.Value == ipStr);

            var entry = new BanEntry
            {
                Value = ipStr,
                Reason = reason ?? "Banned by admin",
                BannedAt = DateTime.UtcNow,
            };

            _ipBans.Add(entry);
            Save();
            return entry;
        }
    }

    public bool UnbanIp(string ip)
    {
        EnsureLoaded();

        lock (_lock)
        {
            var removed = _ipBans.RemoveAll(b => b.Value == ip) > 0;
            if (removed)
            {
                Save();
            }

            return removed;
        }
    }

    public IReadOnlyList<BanEntry> AllIpBans()
    {
        EnsureLoaded();

        lock (_lock)
        {
            return _ipBans.ToList();
        }
    }

    public (int ipBans, int fcBans) Stats()
    {
        EnsureLoaded();

        lock (_lock)
        {
            return (_ipBans.Count, 0);
        }
    }

    private void EnsureLoaded()
    {
        if (_loaded)
        {
            return;
        }

        lock (_lock)
        {
            if (_loaded)
            {
                return;
            }

            if (File.Exists(_filePath))
            {
                try
                {
                    var json = File.ReadAllText(_filePath);
                    _ipBans = JsonSerializer.Deserialize<List<BanEntry>>(json) ?? new List<BanEntry>();
                }
                catch
                {
                    _ipBans = new List<BanEntry>();
                }
            }

            _loaded = true;
        }
    }

    private void Save()
    {
        try
        {
            var json = JsonSerializer.Serialize(_ipBans, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_filePath, json);
        }
        catch
        {
        }
    }

    private static string NormalizeIp(IPAddress ip)
        => ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4().ToString() : ip.ToString();
}

public class BanEntry
{
    public string Value { get; init; } = string.Empty;

    public string Reason { get; init; } = string.Empty;

    public DateTime BannedAt { get; init; }
}
