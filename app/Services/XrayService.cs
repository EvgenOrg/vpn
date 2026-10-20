using System.Diagnostics;
using System.Net.Sockets;
using System.Text.Json;

namespace SecurityVpn.Services;

/// <summary>Запускает ядро Xray (core\xray.exe) с клиентским конфигом VLESS + Reality и читает из него статистику трафика.</summary>
internal sealed class XrayService
{
    public const int SocksPort = 10808;
    public const int HttpPort = 10809;
    public const int ApiPort = 10085;

    private Process? _process;
    private string? _configPath;
    private readonly Queue<string> _tail = new();
    private long _lastUp, _lastDown;
    private DateTime _lastSample;

    public static bool IsInstalled => File.Exists(AppPaths.XrayExe);
    public bool IsRunning => _process is { HasExited: false };

    public async Task StartAsync(ServerDto server, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        Stop();
        KillStrays();

        _configPath = Path.Combine(AppPaths.DataDir, "xray-config.json");
        File.WriteAllText(_configPath, BuildConfig(server));

        var info = new ProcessStartInfo(AppPaths.XrayExe)
        {
            ArgumentList = { "run", "-config", _configPath },
            WorkingDirectory = AppPaths.CoreDir,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        info.Environment["XRAY_LOCATION_ASSET"] = AppPaths.CoreDir;

        var process = Process.Start(info) ?? throw new UserException("Не удалось запустить ядро VPN.");
        process.OutputDataReceived += (_, e) => Remember(e.Data);
        process.ErrorDataReceived += (_, e) => Remember(e.Data);
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        _process = process;

        var deadline = DateTime.UtcNow.AddSeconds(8);
        while (DateTime.UtcNow < deadline)
        {
            ct.ThrowIfCancellationRequested();
            if (process.HasExited)
                throw new UserException("Ядро VPN сразу остановилось. " + LastLogLine());
            if (await PortOpenAsync(HttpPort).ConfigureAwait(true))
                return;
            await Task.Delay(150, ct).ConfigureAwait(true);
        }
        throw new UserException("Ядро VPN запустилось, но не открыло локальный порт. " + LastLogLine());
    }

    public void Stop()
    {
        var process = _process;
        _process = null;
        if (process is not null)
        {
            try { if (!process.HasExited) { process.Kill(true); process.WaitForExit(3000); } } catch { /* уже завершён */ }
            process.Dispose();
        }
        if (_configPath is not null)
        {
            try { File.Delete(_configPath); } catch { /* не критично */ }
            _configPath = null;
        }
        _lastSample = default;
    }

    /// <summary>Скорость в байтах/с по счётчикам Xray. null, пока нет двух замеров.</summary>
    public async Task<(double Down, double Up)?> SampleSpeedAsync(CancellationToken ct)
    {
        if (!IsRunning) return null;

        var info = new ProcessStartInfo(AppPaths.XrayExe)
        {
            ArgumentList = { "api", "statsquery", "-s", $"127.0.0.1:{ApiPort}", "-pattern", "outbound>>>proxy>>>traffic" },
            WorkingDirectory = AppPaths.CoreDir,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(3000);

        string output;
        try
        {
            using var process = Process.Start(info);
            if (process is null) return null;
            output = await process.StandardOutput.ReadToEndAsync(timeout.Token).ConfigureAwait(false);
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return null; // не дождались ответа: пропускаем этот замер
        }

        long up = 0, down = 0;
        try
        {
            using var doc = JsonDocument.Parse(output);
            if (doc.RootElement.TryGetProperty("stat", out var stats) && stats.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in stats.EnumerateArray())
                {
                    var name = item.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
                    var value = ReadLong(item);
                    if (name.EndsWith("uplink", StringComparison.Ordinal)) up = value;
                    else if (name.EndsWith("downlink", StringComparison.Ordinal)) down = value;
                }
            }
        }
        catch (JsonException)
        {
            return null;
        }

        var now = DateTime.UtcNow;
        (double, double)? result = null;
        if (_lastSample != default)
        {
            var seconds = Math.Max(0.1, (now - _lastSample).TotalSeconds);
            result = (Math.Max(0, down - _lastDown) / seconds, Math.Max(0, up - _lastUp) / seconds);
        }
        _lastSample = now;
        _lastDown = down;
        _lastUp = up;
        return result;
    }

    private static long ReadLong(JsonElement item)
    {
        if (!item.TryGetProperty("value", out var v)) return 0;
        return v.ValueKind switch
        {
            JsonValueKind.Number => v.GetInt64(),
            JsonValueKind.String when long.TryParse(v.GetString(), out var parsed) => parsed,
            _ => 0,
        };
    }

    private static string BuildConfig(ServerDto s)
    {
        var config = new
        {
            log = new { loglevel = "warning" },
            stats = new { },
            api = new { tag = "api", services = new[] { "StatsService" } },
            policy = new { system = new { statsOutboundUplink = true, statsOutboundDownlink = true } },
            inbounds = new object[]
            {
                new
                {
                    tag = "socks", listen = "127.0.0.1", port = SocksPort, protocol = "socks",
                    settings = new { udp = true, auth = "noauth" },
                    sniffing = new { enabled = true, destOverride = new[] { "http", "tls", "quic" } },
                },
                new
                {
                    tag = "http", listen = "127.0.0.1", port = HttpPort, protocol = "http",
                    settings = new { },
                },
                new
                {
                    tag = "api", listen = "127.0.0.1", port = ApiPort, protocol = "dokodemo-door",
                    settings = new { address = "127.0.0.1" },
                },
            },
            outbounds = new object[]
            {
                new
                {
                    tag = "proxy", protocol = "vless",
                    settings = new
                    {
                        vnext = new[]
                        {
                            new
                            {
                                address = s.Address, port = s.Port,
                                users = new[] { new { id = s.Uuid, encryption = "none", flow = s.Flow } },
                            },
                        },
                    },
                    streamSettings = new
                    {
                        network = "tcp",
                        security = "reality",
                        realitySettings = new
                        {
                            serverName = s.Sni,
                            fingerprint = s.Fingerprint,
                            publicKey = s.PublicKey,
                            shortId = s.ShortId,
                            spiderX = "",
                        },
                    },
                },
                new { tag = "direct", protocol = "freedom", settings = new { } },
            },
            routing = new
            {
                domainStrategy = "AsIs",
                rules = new[] { new { type = "field", inboundTag = new[] { "api" }, outboundTag = "api" } },
            },
        };
        return JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
    }

    private static async Task<bool> PortOpenAsync(int port)
    {
        try
        {
            using var client = new TcpClient();
            using var cts = new CancellationTokenSource(400);
            await client.ConnectAsync("127.0.0.1", port, cts.Token).ConfigureAwait(false);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Если прошлый запуск закрылся аварийно, в системе мог остаться наш xray.exe, занимающий порты.</summary>
    private static void KillStrays()
    {
        foreach (var p in Process.GetProcessesByName("xray"))
        {
            try
            {
                if (string.Equals(p.MainModule?.FileName, AppPaths.XrayExe, StringComparison.OrdinalIgnoreCase))
                {
                    p.Kill(true);
                    p.WaitForExit(2000);
                }
            }
            catch { /* нет доступа или уже завершён */ }
            finally { p.Dispose(); }
        }
    }

    private void Remember(string? line)
    {
        if (string.IsNullOrWhiteSpace(line)) return;
        lock (_tail)
        {
            _tail.Enqueue(line.Trim());
            while (_tail.Count > 20) _tail.Dequeue();
        }
    }

    private string LastLogLine()
    {
        lock (_tail)
        {
            var last = _tail.LastOrDefault();
            if (last is null) return "";
            return "Подробности: " + (last.Length > 220 ? last[..220] + "…" : last);
        }
    }
}
