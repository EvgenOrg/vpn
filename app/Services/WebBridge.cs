using System.Net;
using System.Text.Json;
using System.Windows;
using Microsoft.Web.WebView2.Core;

namespace SecurityVpn.Services;

/// <summary>
/// Мост между интерфейсом (HTML в WebView2) и C#.
/// Интерфейс шлёт { id, cmd, args }, получает { id, ok, data | error }; события ядра приходят как { event, ... }.
/// </summary>
internal sealed class WebBridge
{
    private static readonly JsonSerializerOptions Out = new(JsonSerializerDefaults.Web);

    private readonly CoreWebView2 _web;
    private readonly Window _window;
    private readonly string? _configError;
    private readonly ApiClient? _api;
    private readonly VpnController? _vpn;

    public WebBridge(CoreWebView2 web, Window window)
    {
        _web = web;
        _window = window;

        try
        {
            var config = AppConfig.Load();
            _api = new ApiClient(config);
            _vpn = new VpnController(_api);
            _vpn.Emit += Send;
        }
        catch (UserException ex)
        {
            _configError = ex.Message;
        }
    }

    public void Shutdown() => _vpn?.Dispose();

    public async void OnMessage(string json)
    {
        var id = 0;
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            id = root.GetProperty("id").GetInt32();
            var cmd = root.GetProperty("cmd").GetString() ?? "";
            var args = root.TryGetProperty("args", out var a) ? a : default;

            var data = await DispatchAsync(cmd, args);
            Send(new { id, ok = true, data });
        }
        catch (UserException ex)
        {
            Send(new { id, ok = false, error = ex.Message });
        }
        catch (Exception ex)
        {
            Send(new { id, ok = false, error = "Внутренняя ошибка: " + ex.Message });
        }
    }

    private async Task<object?> DispatchAsync(string cmd, JsonElement args)
    {
        switch (cmd)
        {
            case "init":
                return await InitAsync();

            case "login":
            {
                var result = await Api.LoginAsync(Str(args, "username"), Str(args, "password"), CancellationToken.None);
                return Authenticated(result);
            }

            case "register":
            {
                var result = await Api.RegisterAsync(Str(args, "username"), Str(args, "password"), Str(args, "invite"), CancellationToken.None);
                return Authenticated(result);
            }

            case "changePassword":
                await Api.ChangePasswordAsync(Str(args, "oldPassword"), Str(args, "newPassword"), CancellationToken.None);
                return new { };

            case "logout":
                await LogoutAsync();
                return new { };

            case "connect":
                Vpn.StartConnect();
                return new { };

            case "disconnect":
                Vpn.Disconnect();
                return new { };

            case "window":
                WindowAction(Str(args, "action"));
                return new { };

            default:
                throw new UserException("Неизвестная команда: " + cmd);
        }
    }

    private async Task<object> InitAsync()
    {
        if (_configError is not null)
            return new { configError = _configError };

        InfoDto? info = null;
        string? offline = null;
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            info = await Api.InfoAsync(cts.Token);
        }
        catch (UserException ex)
        {
            offline = ex.Message;
        }

        string? username = null;
        var token = SessionStore.Load();
        if (token is not null && offline is null)
        {
            Api.Token = token;
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                username = (await Api.MeAsync(cts.Token)).Username;
            }
            catch (ApiException ex) when (ex.Status is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            {
                SessionStore.Clear();
                Api.Token = null;
            }
            catch (UserException)
            {
                Api.Token = null; // сети нет: покажем вход, сохранённый токен останется до следующего запуска
            }
        }

        return new
        {
            name = info?.Name ?? "Security VPN",
            inviteRequired = info?.InviteRequired ?? false,
            location = info?.Location,
            loggedIn = username is not null,
            username,
            state = Vpn.StateName,
            since = Vpn.SinceMs,
            message = Vpn.Message,
            offline,
        };
    }

    private object Authenticated(AuthDto auth)
    {
        Api.Token = auth.Token;
        SessionStore.Save(auth.Token);
        return new { username = auth.User.Username };
    }

    private async Task LogoutAsync()
    {
        Vpn.Disconnect();
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await Api.LogoutAsync(cts.Token);
        }
        catch (UserException)
        {
            // сервер недоступен: локально всё равно выходим
        }
        SessionStore.Clear();
        Api.Token = null;
    }

    private void WindowAction(string action)
    {
        switch (action)
        {
            case "minimize":
                _window.WindowState = WindowState.Minimized;
                break;
            case "close":
                _window.Close();
                break;
            case "drag":
                try { _window.DragMove(); } catch (InvalidOperationException) { /* кнопка мыши уже отпущена */ }
                break;
        }
    }

    private ApiClient Api => _api ?? throw new UserException(_configError ?? "Приложение не настроено.");
    private VpnController Vpn => _vpn ?? throw new UserException(_configError ?? "Приложение не настроено.");

    private static string Str(JsonElement args, string name) =>
        args.ValueKind == JsonValueKind.Object &&
        args.TryGetProperty(name, out var v) &&
        v.ValueKind == JsonValueKind.String
            ? v.GetString() ?? ""
            : "";

    /// <summary>Отправка в интерфейс из любого потока.</summary>
    private void Send(object payload)
    {
        var json = JsonSerializer.Serialize(payload, Out);
        if (_window.Dispatcher.CheckAccess()) Post(json);
        else _window.Dispatcher.BeginInvoke(new Action(() => Post(json)));
    }

    private void Post(string json)
    {
        try { _web.PostWebMessageAsJson(json); }
        catch (ObjectDisposedException) { /* окно уже закрывается */ }
        catch (InvalidOperationException) { /* WebView2 уже выгружен */ }
    }
}
