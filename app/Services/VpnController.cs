using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace SecurityVpn.Services;

/// <summary>
/// Управляет подключением: получает настройки с сервера, запускает ядро, проверяет, что канал работает,
/// и только потом включает системный прокси Windows. Все методы вызываются из потока интерфейса.
/// </summary>
internal sealed class VpnController : IDisposable
{
    private readonly ApiClient _api;
    private readonly XrayService _xray = new();
    private readonly SynchronizationContext _ui;
    private CancellationTokenSource? _connectCts;
    private CancellationTokenSource? _statsCts;
    private long _sinceMs;
    private int _generation; // растёт при каждой попытке и при отключении: «устаревшая» попытка ничего не трогает

    public string StateName { get; private set; } = "disconnected";
    public string Message { get; private set; } = "";
    public long SinceMs => _sinceMs;

    /// <summary>События для интерфейса: { event: "state" | "stats" | "sessionExpired", ... }.</summary>
    public event Action<object>? Emit;

    public VpnController(ApiClient api)
    {
        _api = api;
        _ui = SynchronizationContext.Current ?? new SynchronizationContext();
    }

    public async void StartConnect()
    {
        // async void безопасен: ConnectAsync сам ловит все исключения
        await ConnectAsync();
    }

    private async Task ConnectAsync()
    {
        if (StateName is "connecting" or "connected") return;

        _connectCts?.Dispose();
        _connectCts = new CancellationTokenSource();
        var ct = _connectCts.Token;
        var generation = ++_generation;
        SetState("connecting", "Получаем настройки…");

        try
        {
            if (!XrayService.IsInstalled)
                throw new UserException("Не найдено ядро VPN (core\\xray.exe). Запустите get-xray.ps1 из папки app и перезапустите приложение.");

            var server = await WaitForConfigAsync(ct);

            SetState("connecting", "Запускаем защищённый канал…");
            await _xray.StartAsync(server, ct);

            SetState("connecting", "Проверяем соединение…");
            if (!await ProbeAsync(ct))
                throw new UserException("Сервер не отвечает. Проверьте, что на сервере запущен Xray и открыт порт 443.");

            ct.ThrowIfCancellationRequested();
            SystemProxy.Enable();
            _sinceMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            SetState("connected", "");
            StartStats(server);
        }
        catch (OperationCanceledException)
        {
            if (generation != _generation) return; // пользователь уже нажал «отключить» или начал новую попытку
            Cleanup();
            SetState("disconnected", "");
        }
        catch (ApiException ex) when (ex.Status == HttpStatusCode.Unauthorized)
        {
            if (generation != _generation) return;
            Cleanup();
            SessionStore.Clear();
            _api.Token = null;
            SetState("disconnected", "");
            Emit?.Invoke(new { @event = "sessionExpired", message = ex.Message });
        }
        catch (UserException ex)
        {
            if (generation != _generation) return;
            Cleanup();
            SetState("error", ex.Message);
        }
        catch (Exception ex)
        {
            if (generation != _generation) return;
            Cleanup();
            SetState("error", "Непредвиденная ошибка: " + ex.Message);
        }
    }

    public void Disconnect()
    {
        _generation++;
        _connectCts?.Cancel();
        Cleanup();
        SetState("disconnected", "");
    }

    public void Dispose()
    {
        Cleanup();
        _connectCts?.Dispose();
    }

    private async Task<ServerDto> WaitForConfigAsync(CancellationToken ct)
    {
        var started = DateTime.UtcNow;
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            var config = await _api.ConfigAsync(ct);
            if (config.Status == "ready" && config.Server is not null)
                return config.Server;

            // 202: аккаунт создан, но сервер ещё не добавил его в Xray (до ~15 секунд)
            if (DateTime.UtcNow - started > TimeSpan.FromSeconds(45))
                throw new UserException("Сервер ещё применяет настройки вашего аккаунта. Повторите через минуту.");
            SetState("connecting", "Сервер готовит ваш доступ…");
            await Task.Delay(2000, ct);
        }
    }

    /// <summary>Запрос через локальный прокси: убеждаемся, что туннель реально пропускает трафик, прежде чем трогать настройки Windows.</summary>
    private static async Task<bool> ProbeAsync(CancellationToken ct)
    {
        using var handler = new HttpClientHandler
        {
            Proxy = new WebProxy($"http://127.0.0.1:{XrayService.HttpPort}"),
            UseProxy = true,
        };
        using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(8) };

        for (var attempt = 0; attempt < 3; attempt++)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var response = await http.GetAsync("http://cp.cloudflare.com/generate_204", ct);
                if ((int)response.StatusCode < 400) return true;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                // таймаут или обрыв: попробуем ещё раз
            }
            await Task.Delay(1000, ct);
        }
        return false;
    }

    private void StartStats(ServerDto server)
    {
        _statsCts?.Cancel();
        _statsCts = new CancellationTokenSource();
        var ct = _statsCts.Token;

        _ = Task.Run(async () =>
        {
            var tick = 0;
            double ping = 0;
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    if (!_xray.IsRunning)
                    {
                        _ui.Post(_ => OnCoreStopped(), null);
                        return;
                    }
                    if (tick % 3 == 0) ping = await MeasurePingAsync(server, ct);
                    var speed = await _xray.SampleSpeedAsync(ct);
                    Emit?.Invoke(new { @event = "stats", down = speed?.Down ?? 0, up = speed?.Up ?? 0, ping });
                    tick++;
                    await Task.Delay(2000, ct);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch
                {
                    await Task.Delay(2000, ct).ContinueWith(_ => { }); // не крутимся вхолостую при сбое
                }
            }
        }, ct);
    }

    private void OnCoreStopped()
    {
        if (StateName != "connected") return;
        Cleanup();
        SetState("error", "Соединение прервано: ядро VPN остановилось. Нажмите кнопку, чтобы подключиться снова.");
    }

    /// <summary>Время установки TCP-соединения с сервером, в миллисекундах (0, если не удалось).</summary>
    private static async Task<double> MeasurePingAsync(ServerDto server, CancellationToken ct)
    {
        try
        {
            using var client = new TcpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(2500);
            var watch = Stopwatch.StartNew();
            await client.ConnectAsync(server.Address, server.Port, cts.Token);
            return watch.Elapsed.TotalMilliseconds;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return 0;
        }
    }

    private void Cleanup()
    {
        _statsCts?.Cancel();
        _statsCts = null;
        try { SystemProxy.Restore(); } catch { /* вернём при следующем запуске */ }
        _xray.Stop();
        _sinceMs = 0;
    }

    private void SetState(string state, string message)
    {
        StateName = state;
        Message = message;
        Emit?.Invoke(new { @event = "state", state, message, since = _sinceMs });
    }
}
