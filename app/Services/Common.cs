using System.Net;
using System.Text.Json;

namespace SecurityVpn.Services;

/// <summary>Ошибка, текст которой безопасно показать пользователю как есть.</summary>
internal class UserException : Exception
{
    public UserException(string message) : base(message) { }
}

/// <summary>Ошибка ответа API (с HTTP-статусом).</summary>
internal sealed class ApiException : UserException
{
    public HttpStatusCode Status { get; }
    public ApiException(string message, HttpStatusCode status) : base(message) => Status = status;
}

internal static class AppPaths
{
    public static string BaseDir => AppContext.BaseDirectory;
    public static string WebDir => Path.Combine(BaseDir, "Web");
    public static string CoreDir => Path.Combine(BaseDir, "core");
    public static string XrayExe => Path.Combine(CoreDir, "xray.exe");

    /// <summary>%LocalAppData%\SecurityVPN: сессия, резервная копия настроек прокси, кэш WebView2.</summary>
    public static string DataDir { get; } = EnsureDir(
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecurityVPN"));

    private static string EnsureDir(string path)
    {
        Directory.CreateDirectory(path);
        return path;
    }
}

/// <summary>Настройки из config.json: адрес API и отпечаток его сертификата.</summary>
internal sealed class AppConfig
{
    public string ApiUrl { get; private init; } = "";
    public string CertSha256 { get; private init; } = "";

    private sealed class Raw
    {
        public string? ApiUrl { get; set; }
        public string? CertSha256 { get; set; }
    }

    public static AppConfig Load()
    {
        var path = new[] { Path.Combine(AppPaths.BaseDir, "config.json"), Path.Combine(AppPaths.DataDir, "config.json") }
            .FirstOrDefault(File.Exists);
        if (path is null)
        {
            throw new UserException(
                "Не найден config.json. Скопируйте config.example.json в config.json (в папке app), " +
                "впишите apiUrl и certSha256, которые вывел install.sh на сервере, и запустите приложение снова.");
        }

        Raw? raw;
        try
        {
            raw = JsonSerializer.Deserialize<Raw>(File.ReadAllText(path), new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                ReadCommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true,
            });
        }
        catch (JsonException ex)
        {
            throw new UserException("config.json повреждён: " + ex.Message);
        }

        var url = (raw?.ApiUrl ?? "").Trim().TrimEnd('/');
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
            throw new UserException("В config.json поле apiUrl должно быть вида https://IP-СЕРВЕРА:8443");

        var pin = (raw?.CertSha256 ?? "").Replace(":", "").Replace(" ", "").Trim();
        if (pin.Length != 64 || !pin.All(Uri.IsHexDigit))
        {
            throw new UserException(
                "В config.json поле certSha256 должно быть SHA-256 отпечатком сертификата сервера (64 hex-символа). " +
                "Его печатает install.sh в конце установки.");
        }

        return new AppConfig { ApiUrl = url, CertSha256 = pin.ToUpperInvariant() };
    }
}
