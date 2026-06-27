using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Impostor.Api.Games;
using Impostor.Api.Games.Managers;
using Impostor.Api.Innersloth;
using Impostor.Api.Net;
using Impostor.Api.Net.Manager;
using Impostor.Plugins.Admin.Stores;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

#nullable enable

namespace Impostor.Plugins.Admin.Http;

[ApiController]
public sealed class AdminController : ControllerBase
{
    private const string DefaultPassword = "CHANGE-ME";
    private const string CookieName = "impostor_admin";
    private const int MaxLoginAttempts = 5;
    private static readonly TimeSpan BruteForceWindow = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan SessionExpiry = TimeSpan.FromHours(8);
    private static readonly TimeSpan PasswordHashCacheDuration = TimeSpan.FromSeconds(10);

    private static readonly DateTime StartTime = DateTime.UtcNow;

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, DateTime> Sessions = new();

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, (int Count, DateTime BlockedUntil)> FailedLogins = new();

    private static readonly object PasswordLock = new();
    private static byte[]? CachedPasswordHash;
    private static DateTime PasswordHashCacheTime = DateTime.MinValue;
    private static bool? CachedIsDefaultPassword;
    private static DateTime DefaultPasswordCheckTime = DateTime.MinValue;

    private readonly ILogger<AdminController> _logger;
    private readonly IGameManager _gameManager;
    private readonly IClientManager _clientManager;
    private readonly BanStore _bans;

    public AdminController(
        ILogger<AdminController> logger,
        IGameManager gameManager,
        IClientManager clientManager,
        BanStore bans)
    {
        _logger = logger;
        _gameManager = gameManager;
        _clientManager = clientManager;
        _bans = bans;
    }

    private byte[] GetPasswordHash()
    {
        lock (PasswordLock)
        {
            if (CachedPasswordHash != null && DateTime.UtcNow - PasswordHashCacheTime < PasswordHashCacheDuration)
            {
                return CachedPasswordHash;
            }
        }

        var dir = Path.Combine(Directory.GetCurrentDirectory(), "Admin");
        Directory.CreateDirectory(dir);

        var path = Path.Combine(dir, "password.txt");
        if (!System.IO.File.Exists(path))
        {
            System.IO.File.WriteAllText(path, DefaultPassword);
            _logger.LogWarning("[Admin] Created Admin/password.txt with default password. CHANGE IT IMMEDIATELY!");
        }

        var pw = System.IO.File.ReadAllText(path).Trim();
        if (string.IsNullOrEmpty(pw))
        {
            pw = DefaultPassword;
        }

        var hash = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(pw));

        lock (PasswordLock)
        {
            CachedPasswordHash = hash;
            PasswordHashCacheTime = DateTime.UtcNow;
        }

        return hash;
    }

    public static bool IsDefaultPassword()
    {
        lock (PasswordLock)
        {
            if (CachedIsDefaultPassword.HasValue && DateTime.UtcNow - DefaultPasswordCheckTime < PasswordHashCacheDuration)
            {
                return CachedIsDefaultPassword.Value;
            }
        }

        var dir = Path.Combine(Directory.GetCurrentDirectory(), "Admin");
        var path = Path.Combine(dir, "password.txt");

        string pw;
        if (!System.IO.File.Exists(path))
        {
            pw = DefaultPassword;
        }
        else
        {
            pw = System.IO.File.ReadAllText(path).Trim();
            if (string.IsNullOrEmpty(pw))
            {
                pw = DefaultPassword;
            }
        }

        var isDefault = pw == DefaultPassword;

        lock (PasswordLock)
        {
            CachedIsDefaultPassword = isDefault;
            DefaultPasswordCheckTime = DateTime.UtcNow;
        }

        return isDefault;
    }

    private static bool VerifyPassword(string password, byte[] expectedHash)
    {
        var actualHash = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(password));
        return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
    }

    private bool IsAuthenticated()
    {
        if (!Request.Cookies.TryGetValue(CookieName, out var token))
        {
            return false;
        }

        // Check if session token is valid and not expired.
        if (Sessions.TryGetValue(token, out var expiry))
        {
            if (DateTime.UtcNow < expiry)
            {
                // Renew expiry on each request (sliding).
                Sessions[token] = DateTime.UtcNow + SessionExpiry;
                return true;
            }

            Sessions.TryRemove(token, out _);
        }

        return false;
    }

    private bool IsBruteForceBlocked(string ip)
    {
        if (FailedLogins.TryGetValue(ip, out var entry))
        {
            if (DateTime.UtcNow < entry.BlockedUntil)
            {
                return true;
            }

            if (entry.Count >= MaxLoginAttempts)
            {
                FailedLogins.TryRemove(ip, out _);
            }
        }

        return false;
    }

    private bool RecordFailedLogin(string ip)
    {
        var now = DateTime.UtcNow;
        FailedLogins.AddOrUpdate(
            ip,
            _ => (1, now + BruteForceWindow),
            (_, existing) =>
            {
                // Reset if window expired.
                if (now > existing.BlockedUntil && existing.Count < MaxLoginAttempts)
                {
                    return (1, now + BruteForceWindow);
                }

                var newCount = existing.Count + 1;
                if (newCount >= MaxLoginAttempts)
                {
                    return (newCount, now + BruteForceWindow);
                }

                return (newCount, existing.BlockedUntil);
            });

        return IsBruteForceBlocked(ip);
    }


    [HttpGet("/admin")]
    public IActionResult Panel()
    {
        if (!IsAuthenticated())
        {
            return Content(LoginHtml, "text/html; charset=utf-8");
        }

        var html = AdminHtml;
        if (IsDefaultPassword())
        {
            // Inject a red warning banner at the top of the page.
            html = html.Replace("<!--WARN-->",
                """
                <div style="background:rgba(248,81,73,.15);border-bottom:2px solid var(--r);color:var(--r);text-align:center;padding:8px 16px;font-size:13px;font-weight:600">
                    &#9888; You are using the default password! Change it in <code>Admin/password.txt</code> immediately.
                </div>
                """);
        }

        return Content(html, "text/html; charset=utf-8");
    }

    [HttpPost("/admin/login")]
    public IActionResult Login([FromForm] string password)
    {
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        if (IsBruteForceBlocked(ip))
        {
            _logger.LogWarning("[Admin] Blocked login attempt from {Ip} (brute-force protection)", ip);
            return Content(
                LoginHtml.Replace("<!--ERR-->",
                    "<p style='color:var(--r);margin-top:8px'>Too many failed attempts. Try again in 5 minutes.</p>"),
                "text/html; charset=utf-8");
        }

        var expectedHash = GetPasswordHash();

        if (!VerifyPassword(password, expectedHash))
        {
            var blocked = RecordFailedLogin(ip);
            _logger.LogWarning("[Admin] Failed login from {Ip}", ip);

            var msg = blocked
                ? "Too many failed attempts. Try again in 5 minutes."
                : "Incorrect password.";

            return Content(
                LoginHtml.Replace("<!--ERR-->",
                    $"<p style='color:var(--r);margin-top:8px'>{msg}</p>"),
                "text/html; charset=utf-8");
        }

        FailedLogins.TryRemove(ip, out _);

        var token = Guid.NewGuid().ToString("N");
        Sessions[token] = DateTime.UtcNow + SessionExpiry;

        Response.Cookies.Append(CookieName, token, new CookieOptions
        {
            HttpOnly = true,
            Secure = Request.IsHttps,
            SameSite = SameSiteMode.Strict,
            MaxAge = SessionExpiry,
        });

        _logger.LogInformation("[Admin] Successful login from {Ip}", ip);
        return Redirect("/admin");
    }

    [HttpPost("/admin/logout")]
    public IActionResult Logout()
    {
        if (Request.Cookies.TryGetValue(CookieName, out var token))
        {
            Sessions.TryRemove(token, out _);
        }

        Response.Cookies.Delete(CookieName);
        return Redirect("/admin");
    }

    [HttpGet("/api/admin/status")]
    public IActionResult Status()
    {
        if (!IsAuthenticated())
        {
            return Unauthorized();
        }

        var up = DateTime.UtcNow - StartTime;
        var games = _gameManager.Games.ToList();
        var (ib, fb) = _bans.Stats();

        return Ok(new
        {
            uptime = Fmt(up),
            uptimeSeconds = (long)up.TotalSeconds,
            startTime = StartTime.ToString("yyyy-MM-dd HH:mm:ss") + " UTC",
            totalGames = games.Count,
            totalPlayers = _clientManager.Clients.Count(),
            publicGames = games.Count(g => g.IsPublic),
            activeGames = games.Count(g => g.GameState == GameStates.Started),
            bannedIps = ib,
            bannedFriendCodes = fb,
            runtime = RuntimeInformation.FrameworkDescription,
            os = RuntimeInformation.OSDescription,
            pid = Environment.ProcessId,
        });
    }

    [HttpGet("/api/admin/games")]
    public IActionResult GetGames()
    {
        if (!IsAuthenticated())
        {
            return Unauthorized();
        }

        return Ok(_gameManager.Games.Select(Snap));
    }

    [HttpGet("/api/admin/clients")]
    public IActionResult GetClients()
    {
        if (!IsAuthenticated())
        {
            return Unauthorized();
        }

        return Ok(_clientManager.Clients.Select(CSnap));
    }

    [HttpGet("/api/admin/bans")]
    public IActionResult GetBans()
    {
        if (!IsAuthenticated())
        {
            return Unauthorized();
        }

        return Ok(new
        {
            ips = _bans.AllIpBans(),
            friendCodes = Array.Empty<BanEntry>(),
        });
    }

    [HttpPost("/api/admin/broadcast")]
    public async Task<IActionResult> Broadcast([FromBody] BroadcastReq req)
    {
        if (!IsAuthenticated())
        {
            return Unauthorized();
        }

        if (string.IsNullOrWhiteSpace(req.Message))
        {
            return BadRequest(Err("Message required"));
        }

        var sent = 0;
        foreach (var g in _gameManager.Games)
        {
            var host = g.Host?.Character;
            if (host != null)
            {
                await host.SendChatAsync($"[Server] {req.Message}");
                sent++;
            }
        }

        return Ok(new { sent });
    }

    [HttpPost("/api/admin/message")]
    public async Task<IActionResult> GameMessage([FromBody] GameMsgReq req)
    {
        if (!IsAuthenticated())
        {
            return Unauthorized();
        }

        var game = FindGame(req.GameCode);
        if (game == null)
        {
            return NotFound(Err($"Game '{req.GameCode}' not found"));
        }

        var host = game.Host?.Character;
        if (host == null)
        {
            return BadRequest(Err("No host character"));
        }

        await host.SendChatAsync($"[Admin] {req.Message}");
        return Ok(new { ok = true });
    }

    [HttpPost("/api/admin/kick")]
    public async Task<IActionResult> Kick([FromBody] ClientIdReq req)
    {
        if (!IsAuthenticated())
        {
            return Unauthorized();
        }

        var c = FindClient(req.ClientId);
        if (c == null)
        {
            return NotFound(Err($"Client {req.ClientId} not found"));
        }

        var reason = req.Reason ?? "Kicked by admin";
        await c.DisconnectAsync(DisconnectReason.Custom, reason);

        if (c.Player != null)
        {
            await c.Player.KickAsync();
        }

        return Ok(new { kicked = true, name = c.Name });
    }

    [HttpPost("/api/admin/ban/ip")]
    public async Task<IActionResult> BanIp([FromBody] BanIpReq req)
    {
        if (!IsAuthenticated())
        {
            return Unauthorized();
        }

        if (!IPAddress.TryParse(req.Ip, out var ip))
        {
            return BadRequest(Err("Invalid IP"));
        }

        var entry = _bans.BanIp(ip, req.Reason ?? "Banned by admin");
        var kicked = 0;
        foreach (var c in _clientManager.Clients.ToList())
        {
            var cip = c.Connection?.EndPoint?.Address;
            if (cip != null && Norm(cip) == Norm(ip))
            {
                var reason = req.Reason ?? "Banned by admin";
                await c.DisconnectAsync(DisconnectReason.Custom, reason);

                if (c.Player != null)
                {
                    await c.Player.BanAsync();
                }

                kicked++;
            }
        }

        return Ok(new { banned = entry.Value, disconnected = kicked });
    }

    [HttpPost("/api/admin/unban/ip")]
    public IActionResult UnbanIp([FromBody] UnbanReq req)
    {
        if (!IsAuthenticated())
        {
            return Unauthorized();
        }

        return Ok(new { removed = _bans.UnbanIp(req.Value) });
    }

    [HttpPost("/api/admin/game/end")]
    public async Task<IActionResult> EndGame([FromBody] GameCodeReq req)
    {
        if (!IsAuthenticated())
        {
            return Unauthorized();
        }

        var g = FindGame(req.GameCode);
        if (g == null)
        {
            return NotFound(Err($"Game '{req.GameCode}' not found"));
        }

        var players = g.Players.ToList();
        foreach (var p in players)
        {
            await p.Client.DisconnectAsync(DisconnectReason.Custom, req.Reason ?? "Game ended by admin");
            await p.KickAsync();
        }

        return Ok(new { ended = req.GameCode, playersKicked = players.Count });
    }

    [HttpPost("/api/admin/game/public")]
    public async Task<IActionResult> SetPublic([FromBody] GamePublicReq req)
    {
        if (!IsAuthenticated())
        {
            return Unauthorized();
        }

        var g = FindGame(req.GameCode);
        if (g == null)
        {
            return NotFound(Err($"Game '{req.GameCode}' not found"));
        }

        await g.SetPrivacyAsync(req.IsPublic);
        return Ok(new { gameCode = req.GameCode, isPublic = req.IsPublic });
    }

    private IGame? FindGame(string code)
    {
        try
        {
            return _gameManager.Find(new GameCode(code.ToUpperInvariant()));
        }
        catch
        {
            return null;
        }
    }

    private IClient? FindClient(int id)
        => _clientManager.Clients.FirstOrDefault(c => c.Id == id);

    private static object Snap(IGame g) => new
    {
        code = GameCodeParser.IntToGameName(g.Code),
        state = g.GameState.ToString(),
        isPublic = g.IsPublic,
        playerCount = g.PlayerCount,
        maxPlayers = g.Options.MaxPlayers,
        map = g.Options.Map.ToString(),
        impostors = g.Options.NumImpostors,
        host = g.Host?.Client.Name ?? "—",
        players = g.Players.Select(p => new
        {
            id = p.Client.Id,
            name = p.Client.Name,
            isHost = p.IsHost,
            platform = p.Client.PlatformSpecificData?.Platform.ToString() ?? "Unknown",
            ip = p.Client.Connection?.EndPoint?.Address?.ToString() ?? "—",
        }).ToList(),
    };

    private static object CSnap(IClient c) => new
    {
        id = c.Id,
        name = c.Name,
        gameVersion = c.GameVersion.ToString(),
        platform = c.PlatformSpecificData?.Platform.ToString() ?? "Unknown",
        inGame = c.Player != null,
        gameCode = c.Player != null ? GameCodeParser.IntToGameName(c.Player.Game.Code) : "—",
        ip = c.Connection?.EndPoint?.Address?.ToString() ?? "—",
    };

    private static string Norm(IPAddress ip)
        => ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4().ToString() : ip.ToString();

    private static object Err(string msg) => new { error = msg };

    private static string Fmt(TimeSpan t)
    {
        if (t.TotalDays >= 1)
        {
            return $"{(int)t.TotalDays}d {t.Hours}h {t.Minutes}m";
        }

        if (t.TotalHours >= 1)
        {
            return $"{t.Hours}h {t.Minutes}m {t.Seconds}s";
        }

        return $"{t.Minutes}m {t.Seconds}s";
    }


    public sealed record BroadcastReq(string Message);

    public sealed record GameMsgReq(string GameCode, string Message);

    public sealed record ClientIdReq(int ClientId, string? Reason = null);

    public sealed record BanIpReq(string Ip, string? Reason);

    public sealed record UnbanReq(string Value);

    public sealed record GameCodeReq(string GameCode, string? Reason = null);

    public sealed record GamePublicReq(string GameCode, bool IsPublic);

    private const string LoginHtml = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Impostor Admin</title>
    <style>
        :root {
            --bg: #0d1117;
            --s: #161b22;
            --b: #30363d;
            --t: #e6edf3;
            --m: #7d8590;
            --a: #2f81f7;
            --r: #f85149
        }
        * { box-sizing: border-box; margin: 0; padding: 0 }
        body {
            background: var(--bg);
            color: var(--t);
            font: 14px/1.5 'Segoe UI', system-ui, sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center
        }
        .card {
            background: var(--s);
            border: 1px solid var(--b);
            border-radius: 12px;
            padding: 36px 40px;
            width: 340px
        }
        h1 {
            font-size: 18px;
            font-weight: 700;
            margin-bottom: 24px;
            text-align: center;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px
        }
        h1 svg { color: var(--a); flex-shrink: 0 }
        label { display: block; font-size: 12px; color: var(--m); margin-bottom: 5px }
        input {
            width: 100%;
            background: #0d1117;
            border: 1px solid var(--b);
            border-radius: 6px;
            color: var(--t);
            padding: 9px 12px;
            font-size: 14px;
            outline: none;
            margin-bottom: 14px
        }
        input:focus { border-color: var(--a) }
        button {
            width: 100%;
            background: var(--a);
            color: #fff;
            border: none;
            border-radius: 6px;
            padding: 10px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer
        }
        button:hover { opacity: .88 }
    </style>
</head>
<body>
    <div class="card">
        <h1><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>Impostor Admin</h1>
        <form method="POST" action="/admin/login">
            <label>Password</label>
            <input type="password" name="password" autofocus placeholder="Enter admin password">
            <button type="submit">Sign in</button>
            <!--ERR-->
        </form>
    </div>
</body>
</html>
""";

    private const string AdminHtml = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Impostor Admin</title>
    <style>
        :root {
            --bg: #0d1117;
            --s: #161b22;
            --b: #30363d;
            --t: #e6edf3;
            --m: #7d8590;
            --a: #2f81f7;
            --g: #3fb950;
            --y: #d29922;
            --r: #f85149;
            --o: #ffa657
        }
        * { box-sizing: border-box; margin: 0; padding: 0 }
        body {
            background: var(--bg);
            color: var(--t);
            font: 14px/1.5 'Segoe UI', system-ui, sans-serif;
            min-height: 100vh;
            display: flex;
            flex-direction: column
        }
        header {
            background: var(--s);
            border-bottom: 1px solid var(--b);
            padding: 0 20px;
            display: flex;
            align-items: center;
            gap: 12px;
            height: 52px;
            position: sticky;
            top: 0;
            z-index: 100
        }
        header h1 {
            font-size: 15px;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 6px
        }
        .dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--g);
            box-shadow: 0 0 6px var(--g);
            flex-shrink: 0
        }
        .sp { flex: 1 }
        #upd { font-size: 11px; color: var(--m) }
        .logout {
            padding: 5px 12px;
            background: rgba(248, 81, 73, .15);
            color: var(--r);
            border: 1px solid rgba(248, 81, 73, .3);
            border-radius: 6px;
            font-size: 12px;
            cursor: pointer;
            text-decoration: none
        }
        main { display: flex; flex: 1 }
        nav {
            width: 210px;
            background: var(--s);
            border-right: 1px solid var(--b);
            padding: 12px 0;
            flex-shrink: 0;
            position: sticky;
            top: 52px;
            height: calc(100vh - 52px);
            overflow-y: auto
        }
        .ni {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 9px 16px;
            cursor: pointer;
            color: var(--m);
            font-size: 13px;
            border-left: 3px solid transparent;
            transition: all .15s;
            user-select: none
        }
        .ni svg { flex-shrink: 0; width: 16px; height: 16px }
        .ni:hover { color: var(--t); background: rgba(255, 255, 255, .04) }
        .ni.active { color: var(--a); border-left-color: var(--a); background: rgba(47, 129, 247, .08) }
        .nsep { margin: 8px 16px; border-top: 1px solid var(--b) }
        .nlbl {
            padding: 8px 16px 4px;
            font-size: 11px;
            color: var(--m);
            text-transform: uppercase;
            letter-spacing: .5px
        }
        ct { flex: 1; padding: 20px; overflow: hidden }
        .pnl { display: none }
        .pnl.active { display: block }
        .sr {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
            gap: 10px;
            margin-bottom: 20px
        }
        .sc {
            background: var(--s);
            border: 1px solid var(--b);
            border-radius: 8px;
            padding: 14px 18px
        }
        .sc .lbl { color: var(--m); font-size: 11px; text-transform: uppercase; letter-spacing: .5px; margin-bottom: 5px }
        .sc .val { font-size: 26px; font-weight: 700 }
        .sc .sub { font-size: 11px; color: var(--m); margin-top: 3px }
        h2 {
            font-size: 14px;
            font-weight: 600;
            margin-bottom: 14px;
            color: var(--m);
            text-transform: uppercase;
            letter-spacing: .5px;
            display: flex;
            align-items: center;
            gap: 6px
        }
        h2 svg { flex-shrink: 0; width: 16px; height: 16px }
        table { width: 100%; border-collapse: collapse }
        th {
            text-align: left;
            padding: 7px 10px;
            color: var(--m);
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: .5px;
            border-bottom: 1px solid var(--b);
            font-weight: 500
        }
        td { padding: 9px 10px; border-bottom: 1px solid var(--b); vertical-align: top }
        tr:hover td { background: rgba(255, 255, 255, .025) }
        .code { font-family: monospace; color: var(--a); font-weight: 700; letter-spacing: 1px }
        .ip { color: var(--m); font-size: 11px; font-family: monospace }
        .badge {
            display: inline-flex;
            align-items: center;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 11px;
            font-weight: 600
        }
        .bs { background: rgba(63, 185, 80, .15); color: var(--g) }
        .bn { background: rgba(48, 54, 61, .8); color: var(--m) }
        .by { background: rgba(210, 153, 34, .2); color: var(--y) }
        .be { background: rgba(248, 81, 73, .15); color: var(--r) }
        .bpub { background: rgba(63, 185, 80, .12); color: var(--g) }
        .bprv { background: rgba(125, 133, 144, .12); color: var(--m) }
        .chips { display: flex; flex-wrap: wrap; gap: 3px }
        .chip {
            background: rgba(47, 129, 247, .1);
            border: 1px solid rgba(47, 129, 247, .2);
            border-radius: 20px;
            padding: 1px 8px;
            font-size: 11px;
            color: var(--a)
        }
        .chip.host { background: rgba(255, 166, 87, .1); border-color: rgba(255, 166, 87, .25); color: var(--o) }
        .form {
            background: var(--s);
            border: 1px solid var(--b);
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 16px
        }
        .form h3 { font-size: 13px; font-weight: 600; margin-bottom: 12px; color: var(--t); display: flex; align-items: center; gap: 6px }
        .form h3 svg { flex-shrink: 0; width: 16px; height: 16px }
        .field { margin-bottom: 10px }
        .field label { display: block; font-size: 12px; color: var(--m); margin-bottom: 4px }
        input, select, textarea {
            width: 100%;
            background: #0d1117;
            border: 1px solid var(--b);
            border-radius: 6px;
            color: var(--t);
            padding: 7px 10px;
            font-size: 13px;
            outline: none;
            font-family: inherit
        }
        input:focus, select:focus, textarea:focus { border-color: var(--a) }
        textarea { resize: vertical; min-height: 60px }
        .row { display: flex; gap: 8px }
        .row input, .row select { flex: 1 }
        button {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 7px 14px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 500;
            cursor: pointer;
            border: none;
            transition: opacity .15s
        }
        button:hover { opacity: .85 }
        .bp { background: var(--a); color: #fff }
        .bd { background: var(--r); color: #fff }
        .bw { background: var(--y); color: #000 }
        .bsm { padding: 4px 10px; font-size: 12px }
        .msg { padding: 8px 12px; border-radius: 6px; font-size: 12px; margin-top: 8px; display: none }
        .msg.ok { background: rgba(63, 185, 80, .15); color: var(--g); border: 1px solid rgba(63, 185, 80, .3) }
        .msg.err { background: rgba(248, 81, 73, .12); color: var(--r); border: 1px solid rgba(248, 81, 73, .3) }
        .empty { text-align: center; padding: 40px; color: var(--m) }
        .ig {
            display: grid;
            grid-template-columns: 200px 1fr;
            gap: 0;
            background: var(--s);
            border: 1px solid var(--b);
            border-radius: 8px;
            overflow: hidden
        }
        .ik, .iv { padding: 8px 14px; border-bottom: 1px solid var(--b) }
        .ik { color: var(--m); font-size: 12px }
        .iv { font-family: monospace; font-size: 12px }
        .bi {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 8px 12px;
            background: var(--s);
            border: 1px solid var(--b);
            border-radius: 6px;
            margin-bottom: 6px
        }
        .bv { flex: 1; font-family: monospace; font-size: 13px }
        .br2 { font-size: 11px; color: var(--m) }
        .bt { font-size: 11px; color: var(--m); margin-left: auto }
    </style>
</head>
<body>
    <!--WARN-->
    <header>
        <div class="dot" id="dot"></div>
        <h1><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--a)" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>Impostor Admin</h1><span class="sp"></span><span id="upd"></span>
        <form method="POST" action="/admin/logout" style="margin:0"><button class="logout" type="submit">Sign out</button></form>
    </header>
    <main>
        <nav>
            <div class="nlbl">Monitor</div>
            <div class="ni active" onclick="nav('ov')"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 20V10M12 20V4M6 20v-6"/></svg>Overview</div>
            <div class="ni" onclick="nav('gm')"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="6" width="20" height="12" rx="2"/><path d="M6 12h4M14 12h4M12 10v4"/></svg>Games</div>
            <div class="ni" onclick="nav('cl')"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="9" cy="7" r="4"/><path d="M1 20v-2a4 4 0 014-4h8a4 4 0 014 4v2"/><circle cx="17" cy="7" r="4"/><path d="M23 20v-2a4 4 0 00-3-3.87"/></svg>Clients</div>
            <div class="nsep"></div>
            <div class="nlbl">Actions</div>
            <div class="ni" onclick="nav('bc')"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 2H7a2 2 0 00-2 2v16l5-3 5 3V4a2 2 0 00-2-2z"/><path d="M10 9h4M10 13h4"/></svg>Broadcast</div>
            <div class="ni" onclick="nav('ki')"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 5h3l1 4H7l1-4h3V3h2v2zM5 9h14v10a2 2 0 01-2 2H7a2 2 0 01-2-2V9zM10 13v4"/></svg>Kick</div>
            <div class="ni" onclick="nav('ba')"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94L5.62 21a2 2 0 01-2.83-2.83l7.91-7.91a6 6 0 017.94-7.94l-3.76 3.76z"/></svg>Ban</div>
            <div class="ni" onclick="nav('bl')"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M8 8h8M8 12h8M8 16h5"/></svg>Ban List</div>
            <div class="nsep"></div>
            <div class="nlbl">Game Control</div>
            <div class="ni" onclick="nav('ms')"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"/></svg>Message</div>
            <div class="ni" onclick="nav('ge')"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>End Game</div>
            <div class="ni" onclick="nav('gp')"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10M12 2a15.3 15.3 0 00-4 10 15.3 15.3 0 004 10"/></svg>Privacy</div>
            <div class="nsep"></div>
            <div class="nlbl">System</div>
            <div class="ni" onclick="nav('si')"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/></svg>Server Info</div>
        </nav>
        <ct>
            <!-- Overview -->
            <div id="p-ov" class="pnl active">
                <div class="sr">
                    <div class="sc"><div class="lbl">Games</div><div class="val" id="s1">—</div><div class="sub" id="s1b"></div></div>
                    <div class="sc"><div class="lbl">Active</div><div class="val" id="s2">—</div></div>
                    <div class="sc"><div class="lbl">Players</div><div class="val" id="s3">—</div></div>
                    <div class="sc"><div class="lbl">Bans</div><div class="val" id="s4">—</div><div class="sub" id="s4b"></div></div>
                    <div class="sc"><div class="lbl">Uptime</div><div class="val" id="s5" style="font-size:16px">—</div></div>
                </div>
                <h2>Active Games</h2>
                <table><thead><tr><th>Code</th><th>State</th><th>Visibility</th><th>Map</th><th>Players</th><th>Host</th></tr></thead><tbody id="ov-t"><tr><td colspan="6" class="empty">Loading...</td></tr></tbody></table>
            </div>
            <!-- Games -->
            <div id="p-gm" class="pnl">
                <h2>All Games</h2>
                <table><thead><tr><th>Code</th><th>State</th><th>Visibility</th><th>Map</th><th>Players</th><th>Host</th><th>Members</th></tr></thead><tbody id="gm-t"></tbody></table>
            </div>
            <!-- Clients -->
            <div id="p-cl" class="pnl">
                <h2>Clients</h2>
                <table><thead><tr><th>ID</th><th>Name</th><th>IP</th><th>Version</th><th>Platform</th><th>In Game</th></tr></thead><tbody id="cl-t"></tbody></table>
            </div>
            <!-- Broadcast -->
            <div id="p-bc" class="pnl">
                <div class="form">
                    <h3><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 2H7a2 2 0 00-2 2v16l5-3 5 3V4a2 2 0 00-2-2z"/><path d="M10 9h4M10 13h4"/></svg>Broadcast to All Games</h3>
                    <div class="field"><label>Message</label><textarea id="bc-m" placeholder="Message to send to all games..."></textarea></div>
                    <button class="bp" onclick="doBc()">Send to All Games</button>
                    <div id="bc-r" class="msg"></div>
                </div>
            </div>
            <!-- Kick -->
            <div id="p-ki" class="pnl">
                <div class="form">
                    <h3><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 5h3l1 4H7l1-4h3V3h2v2zM5 9h14v10a2 2 0 01-2 2H7a2 2 0 01-2-2V9zM10 13v4"/></svg>Kick by Client ID</h3>
                    <div class="field"><label>Client ID</label><input id="ki-id" type="number" placeholder="Enter client ID"></div>
                    <div class="field"><label>Reason (optional)</label><input id="ki-reason" type="text" placeholder="Reason for kick"></div>
                    <button class="bw" onclick="doKick()">Kick</button>
                    <div id="ki-r" class="msg"></div>
                </div>
                <div class="form">
                    <h3>Quick Kick</h3>
                    <table><thead><tr><th>ID</th><th>Name</th><th>Game</th><th></th></tr></thead><tbody id="ki-t"></tbody></table>
                </div>
            </div>
            <!-- Ban -->
            <div id="p-ba" class="pnl">
                <div class="form">
                    <h3><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94L5.62 21a2 2 0 01-2.83-2.83l7.91-7.91a6 6 0 017.94-7.94l-3.76 3.76z"/></svg>Ban IP</h3>
                    <div class="field"><label>IP Address</label><input id="bi-v" placeholder="1.2.3.4"></div>
                    <div class="field"><label>Reason (optional)</label><input id="bi-r" placeholder="Banned by admin"></div>
                    <button class="bd" onclick="doBanIp()">Ban IP</button>
                    <div id="bi-msg" class="msg"></div>
                </div>
            </div>
            <!-- Ban List -->
            <div id="p-bl" class="pnl">
                <h2>Banned IPs</h2>
                <div id="bl-ip"></div>
            </div>
            <!-- Message -->
            <div id="p-ms" class="pnl">
                <div class="form">
                    <h3><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"/></svg>Message to Game</h3>
                    <div class="row">
                        <div class="field" style="flex:0 0 140px"><label>Game Code</label><input id="ms-c" placeholder="ABCDEF" style="text-transform:uppercase"></div>
                        <div class="field" style="flex:1"><label>Message</label><input id="ms-m" placeholder="Message..."></div>
                    </div>
                    <button class="bp" onclick="doMsg()">Send</button>
                    <div id="ms-r" class="msg"></div>
                </div>
            </div>
            <!-- End Game -->
            <div id="p-ge" class="pnl">
                <div class="form">
                    <h3><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>Force End Game</h3>
                    <div class="field"><label>Game Code</label><input id="ge-c" placeholder="ABCDEF" style="text-transform:uppercase"></div>
                    <div class="field"><label>Reason (optional)</label><input id="ge-reason" type="text" placeholder="Game ended by admin"></div>
                    <button class="bd" onclick="doEnd()">End Game</button>
                    <div id="ge-r" class="msg"></div>
                </div>
                <div class="form">
                    <h3>Active Games</h3>
                    <table><thead><tr><th>Code</th><th>State</th><th>Players</th><th></th></tr></thead><tbody id="ge-t"></tbody></table>
                </div>
            </div>
            <!-- Privacy -->
            <div id="p-gp" class="pnl">
                <div class="form">
                    <h3><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10M12 2a15.3 15.3 0 00-4 10 15.3 15.3 0 004 10"/></svg>Set Game Privacy</h3>
                    <div class="row">
                        <div class="field" style="flex:0 0 140px"><label>Game Code</label><input id="gp-c" placeholder="ABCDEF" style="text-transform:uppercase"></div>
                        <div class="field" style="flex:0 0 140px"><label>Visibility</label><select id="gp-v"><option value="true">Public</option><option value="false">Private</option></select></div>
                    </div>
                    <button class="bp" onclick="doPrivacy()">Apply</button>
                    <div id="gp-r" class="msg"></div>
                </div>
            </div>
            <!-- Server Info -->
            <div id="p-si" class="pnl">
                <h2><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/></svg>Server Info</h2>
                <div class="ig" id="si-d"></div>
            </div>
        </ct>
    </main>
    <script>
        let cur = 'ov';
        function nav(id) {
            document.querySelectorAll('.ni').forEach(e => e.classList.remove('active'));
            event.currentTarget.classList.add('active');
            document.querySelectorAll('.pnl').forEach(e => e.classList.remove('active'));
            document.getElementById('p-' + id).classList.add('active');
            cur = id; refreshTab();
        }
        async function api(m, p, b) {
            const o = { method: m, headers: { 'Content-Type': 'application/json' } };
            if (b) o.body = JSON.stringify(b);
            const r = await fetch(p, o);
            if (r.status === 401) { location.reload(); return { ok: false, data: {} }; }
            try { return { ok: r.ok, data: await r.json() }; }
            catch { return { ok: r.ok, data: {} }; }
        }
        function msg(id, ok, t) {
            const e = document.getElementById(id);
            e.className = 'msg ' + (ok ? 'ok' : 'err');
            e.textContent = t; e.style.display = 'block';
            setTimeout(() => e.style.display = 'none', 4000);
        }
        function e(s) { return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
        function sc(s) { return { Started: 'bs', NotStarted: 'bn', Starting: 'by', Ended: 'be' }[s] || 'bn'; }

        async function fetchStatus() {
            try {
                const { data: d } = await api('GET', '/api/admin/status');
                document.getElementById('s1').textContent = d.totalGames;
                document.getElementById('s1b').textContent = d.publicGames + ' public';
                document.getElementById('s2').textContent = d.activeGames;
                document.getElementById('s3').textContent = d.totalPlayers;
                document.getElementById('s4').textContent = d.bannedIps;
                document.getElementById('s4b').textContent = d.bannedIps + ' IPs';
                document.getElementById('s5').textContent = d.uptime;
                document.getElementById('upd').textContent = 'Updated ' + new Date().toLocaleTimeString();
                document.getElementById('dot').style.background = 'var(--g)';
                document.getElementById('si-d').innerHTML = [
                    ['Started', d.startTime],
                    ['Uptime', d.uptime],
                    ['PID', d.pid],
                    ['Runtime', d.runtime],
                    ['OS', d.os],
                    ['IP Bans', d.bannedIps]
                ].map(([k, v]) => '<div class="ik">' + e(k) + '</div><div class="iv">' + e(v) + '</div>').join('');
            } catch { document.getElementById('dot').style.background = 'var(--r)'; }
        }

        async function fGames(tid, short) {
            const { data: gs } = await api('GET', '/api/admin/games');
            const tb = document.getElementById(tid);
            if (!gs.length) { tb.innerHTML = '<tr><td colspan="' + (short ? 6 : 7) + '" class="empty">No games</td></tr>'; return; }
            tb.innerHTML = gs.map(g => '<tr><td><span class="code">' + e(g.code) + '</span></td><td><span class="badge ' + sc(g.state) + '">' + e(g.state) + '</span></td><td><span class="badge ' + (g.isPublic ? 'bpub' : 'bprv') + '">' + (g.isPublic ? 'Public' : 'Private') + '</span></td><td>' + e(g.map) + '</td><td>' + g.playerCount + '/' + g.maxPlayers + '</td><td>' + e(g.host) + '</td>' + (short ? '' : '<td><div class="chips">' + g.players.map(p => '<span class="chip' + (p.isHost ? ' host' : '') + '" title="' + e(p.ip) + '">' + e(p.name) + '</span>').join('') + '</div></td>') + '</tr>').join('');
        }

        async function fClients() {
            const { data: cs } = await api('GET', '/api/admin/clients');
            const tb = document.getElementById('cl-t');
            if (!cs.length) { tb.innerHTML = '<tr><td colspan="6" class="empty">No clients</td></tr>'; return; }
            tb.innerHTML = cs.map(c => '<tr><td style="color:var(--m)">' + c.id + '</td><td>' + e(c.name) + '</td><td><span class="ip">' + e(c.ip) + '</span></td><td>' + e(c.gameVersion) + '</td><td>' + e(c.platform) + '</td><td>' + (c.inGame ? '<span class="code">' + e(c.gameCode) + '</span>' : '<span style="color:var(--m)">Lobby</span>') + '</td></tr>').join('');
        }

        async function fKickList() {
            const { data: cs } = await api('GET', '/api/admin/clients');
            const tb = document.getElementById('ki-t');
            if (!cs.length) { tb.innerHTML = '<tr><td colspan="4" class="empty">No clients</td></tr>'; return; }
            tb.innerHTML = cs.map(c => '<tr><td style="color:var(--m)">' + c.id + '</td><td>' + e(c.name) + '</td><td>' + (c.inGame ? '<span class="code">' + e(c.gameCode) + '</span>' : '—') + '</td><td><button class="bw bsm" onclick="qkick(' + c.id + ')">Kick</button></td></tr>').join('');
        }

        async function fBans() {
            const { data: d } = await api('GET', '/api/admin/bans');
            document.getElementById('bl-ip').innerHTML = d.ips.length ? d.ips.map(b => bi(b)).join('') : '<div class="empty">No banned IPs</div>';
        }
        function bi(b) {
            return '<div class="bi"><div><div class="bv">' + e(b.value) + '</div><div class="br2">' + e(b.reason) + '</div></div><div class="bt">' + new Date(b.bannedAt).toLocaleString() + '</div><button class="bsm" style="background:rgba(248,81,73,.15);color:var(--r);border:1px solid rgba(248,81,73,.3)" onclick="doUnban(\'' + e(b.value) + '\')">Unban</button></div>';
        }

        async function fGamesEnd() {
            const { data: gs } = await api('GET', '/api/admin/games');
            const tb = document.getElementById('ge-t');
            if (!gs.length) { tb.innerHTML = '<tr><td colspan="4" class="empty">No games</td></tr>'; return; }
            tb.innerHTML = gs.map(g => '<tr><td><span class="code">' + e(g.code) + '</span></td><td><span class="badge ' + sc(g.state) + '">' + e(g.state) + '</span></td><td>' + g.playerCount + '/' + g.maxPlayers + '</td><td><button class="bd bsm" onclick="qend(\'' + e(g.code) + '\')">End</button></td></tr>').join('');
        }

        function refreshTab() {
            if (cur === 'ov') fGames('ov-t', true);
            if (cur === 'gm') fGames('gm-t', false);
            if (cur === 'cl') fClients();
            if (cur === 'ki') fKickList();
            if (cur === 'bl') fBans();
            if (cur === 'ge') fGamesEnd();
        }

        async function doBc() {
            const m = document.getElementById('bc-m').value.trim();
            if (!m) return msg('bc-r', false, 'Message required');
            const { ok, data } = await api('POST', '/api/admin/broadcast', { message: m });
            msg('bc-r', ok, ok ? 'Sent to ' + data.sent + ' game(s)' : (data.error ?? 'Error'));
        }

        async function doKick() {
            const id = parseInt(document.getElementById('ki-id').value);
            if (!id) return msg('ki-r', false, 'Enter client ID');
            const reason = document.getElementById('ki-reason').value.trim();
            const { ok, data } = await api('POST', '/api/admin/kick', { clientId: id, reason: reason || undefined });
            msg('ki-r', ok, ok ? 'Kicked ' + data.name : (data.error ?? 'Error'));
            if (ok) fKickList();
        }

        async function qkick(id) {
            const { ok, data } = await api('POST', '/api/admin/kick', { clientId: id });
            if (!ok) alert(data.error ?? 'Error');
            fKickList();
        }

        async function doBanIp() {
            const v = document.getElementById('bi-v').value.trim(), r = document.getElementById('bi-r').value.trim();
            if (!v) return msg('bi-msg', false, 'IP required');
            const { ok, data } = await api('POST', '/api/admin/ban/ip', { ip: v, reason: r });
            msg('bi-msg', ok, ok ? 'Banned ' + data.banned + ' (' + data.disconnected + ' disconnected)' : (data.error ?? 'Error'));
        }

        async function doUnban(v) {
            await api('POST', '/api/admin/unban/ip', { value: v });
            fBans();
        }

        async function doMsg() {
            const c = document.getElementById('ms-c').value.trim().toUpperCase(), m = document.getElementById('ms-m').value.trim();
            if (!c || !m) return msg('ms-r', false, 'Both game code and message required');
            const { ok, data } = await api('POST', '/api/admin/message', { gameCode: c, message: m });
            msg('ms-r', ok, ok ? 'Sent' : (data.error ?? 'Error'));
        }

        async function doEnd() {
            const c = document.getElementById('ge-c').value.trim().toUpperCase();
            if (!c) return msg('ge-r', false, 'Game code required');
            if (!confirm('End game ' + c + '?')) return;
            const reason = document.getElementById('ge-reason').value.trim();
            const { ok, data } = await api('POST', '/api/admin/game/end', { gameCode: c, reason: reason || undefined });
            msg('ge-r', ok, ok ? 'Ended (' + data.playersKicked + ' kicked)' : (data.error ?? 'Error'));
            if (ok) fGamesEnd();
        }

        async function qend(c) {
            if (!confirm('End ' + c + '?')) return;
            await api('POST', '/api/admin/game/end', { gameCode: c });
            fGamesEnd();
        }

        async function doPrivacy() {
            const c = document.getElementById('gp-c').value.trim().toUpperCase(),
                  p = document.getElementById('gp-v').value === 'true';
            if (!c) return msg('gp-r', false, 'Game code required');
            const { ok, data } = await api('POST', '/api/admin/game/public', { gameCode: c, isPublic: p });
            msg('gp-r', ok, ok ? c + ' -> ' + (p ? 'public' : 'private') : (data.error ?? 'Error'));
        }

        fetchStatus();
        refreshTab();
        setInterval(fetchStatus, 1000);
        setInterval(() => { if (document.visibilityState === 'visible') refreshTab(); }, 1000);
        document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') { fetchStatus(); } });
    </script>
</body>
</html>
""";
}
