using System.Net;
using System.Net.Http.Headers;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SecurityVpn.Services;

internal sealed record LocationDto(string? CountryCode, string? City, double? Lat, double? Lon);
internal sealed record InfoDto(string? Name, bool InviteRequired, LocationDto? Location);
internal sealed record UserDto(string Username);
internal sealed record AuthDto(string Token, UserDto User);
internal sealed record MeDto(string Username);
internal sealed record ServerDto(
    string Address, int Port, string Uuid, string Flow, string Sni,
    string PublicKey, string ShortId, string Fingerprint, LocationDto? Location);
internal sealed record ConfigDto(string Status, ServerDto? Server);

/// <summary>
/// Клиент HTTPS API. Сертификат сервера самоподписанный, поэтому вместо проверки цепочки
/// сверяем SHA-256 отпечаток из config.json: подмена сервера по дороге невозможна.
/// </summary>
internal sealed class ApiClient : IDisposable
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly HttpClient _http;

    public string? Token { get; set; }

    public ApiClient(AppConfig config)
    {
        var pin = config.CertSha256;
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, cert, _, _) =>
                cert is not null &&
                string.Equals(Convert.ToHexString(cert.GetCertHash(HashAlgorithmName.SHA256)), pin, StringComparison.OrdinalIgnoreCase),
        };
        _http = new HttpClient(handler)
        {
            BaseAddress = new Uri(config.ApiUrl + "/api/"),
            Timeout = TimeSpan.FromSeconds(15),
        };
    }

    public Task<InfoDto> InfoAsync(CancellationToken ct) => CallAsync<InfoDto>(HttpMethod.Get, "info", null, false, ct);

    public Task<AuthDto> LoginAsync(string username, string password, CancellationToken ct) =>
        CallAsync<AuthDto>(HttpMethod.Post, "login", new { username, password }, false, ct);

    public Task<AuthDto> RegisterAsync(string username, string password, string invite, CancellationToken ct) =>
        CallAsync<AuthDto>(HttpMethod.Post, "register", new { username, password, invite }, false, ct);

    public Task<MeDto> MeAsync(CancellationToken ct) => CallAsync<MeDto>(HttpMethod.Get, "me", null, true, ct);

    public Task LogoutAsync(CancellationToken ct) => CallAsync<JsonElement>(HttpMethod.Post, "logout", new { }, true, ct);

    public Task ChangePasswordAsync(string oldPassword, string newPassword, CancellationToken ct) =>
        CallAsync<JsonElement>(HttpMethod.Post, "password", new { oldPassword, newPassword }, true, ct);

    public Task<ConfigDto> ConfigAsync(CancellationToken ct) => CallAsync<ConfigDto>(HttpMethod.Get, "config", null, true, ct);

    private async Task<T> CallAsync<T>(HttpMethod method, string path, object? body, bool auth, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(method, path);
        if (body is not null)
            request.Content = new StringContent(JsonSerializer.Serialize(body, Json), Encoding.UTF8, "application/json");
        if (auth && Token is not null)
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token);

        try
        {
            using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
            var text = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

            JsonElement root;
            try
            {
                using var doc = JsonDocument.Parse(text);
                root = doc.RootElement.Clone();
            }
            catch (JsonException)
            {
                throw new UserException("Сервер вернул неожиданный ответ. Проверьте, что API установлен и запущен.");
            }

            if (!response.IsSuccessStatusCode)
            {
                var message = root.ValueKind == JsonValueKind.Object &&
                              root.TryGetProperty("error", out var e) && e.ValueKind == JsonValueKind.String
                    ? e.GetString()!
                    : $"Ошибка сервера ({(int)response.StatusCode})";
                throw new ApiException(message, response.StatusCode);
            }

            return root.Deserialize<T>(Json) ?? throw new UserException("Пустой ответ сервера.");
        }
        catch (HttpRequestException ex) when (ex.InnerException is AuthenticationException)
        {
            throw new UserException(
                "Сертификат сервера не совпал с certSha256 из config.json. Если вы переустанавливали сервер, обновите отпечаток.");
        }
        catch (HttpRequestException)
        {
            throw new UserException("Не удалось связаться с сервером. Проверьте apiUrl в config.json, интернет и открыт ли порт 8443.");
        }
        catch (TaskCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new UserException("Сервер не отвечает (таймаут). Попробуйте ещё раз.");
        }
    }

    public void Dispose() => _http.Dispose();
}
