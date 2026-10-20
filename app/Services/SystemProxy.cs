using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32;

namespace SecurityVpn.Services;

/// <summary>
/// Включает и выключает системный прокси Windows (HKCU, права администратора не нужны).
/// Прежние настройки сохраняются в файл и возвращаются при отключении или при следующем запуске, если приложение закрылось аварийно.
/// </summary>
internal static class SystemProxy
{
    private const string KeyPath = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    private const string Bypass = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;" +
                                  "172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>";

    private static string BackupFile => Path.Combine(AppPaths.DataDir, "proxy-backup.json");
    private static string Ours => $"127.0.0.1:{XrayService.HttpPort}";

    private sealed record Backup(int? ProxyEnable, string? ProxyServer, string? ProxyOverride, string? AutoConfigURL);

    public static void Enable()
    {
        using var key = Registry.CurrentUser.OpenSubKey(KeyPath, writable: true)
                        ?? throw new UserException("Не удалось открыть настройки прокси Windows.");

        if (!File.Exists(BackupFile))
        {
            var backup = new Backup(
                key.GetValue("ProxyEnable") as int?,
                key.GetValue("ProxyServer") as string,
                key.GetValue("ProxyOverride") as string,
                key.GetValue("AutoConfigURL") as string);
            File.WriteAllText(BackupFile, JsonSerializer.Serialize(backup));
        }

        key.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
        key.SetValue("ProxyServer", Ours, RegistryValueKind.String);
        key.SetValue("ProxyOverride", Bypass, RegistryValueKind.String);
        key.DeleteValue("AutoConfigURL", throwOnMissingValue: false); // PAC-скрипт перебил бы наш прокси
        Notify();
    }

    /// <summary>Возвращает прежние настройки. Если мы ничего не меняли, ничего и не делает.</summary>
    public static void Restore()
    {
        if (!File.Exists(BackupFile)) return;

        try
        {
            var backup = JsonSerializer.Deserialize<Backup>(File.ReadAllText(BackupFile));
            using var key = Registry.CurrentUser.OpenSubKey(KeyPath, writable: true);
            if (backup is not null && key is not null)
            {
                // Если пользователь за это время сам поменял прокси, его выбор не трогаем
                var current = key.GetValue("ProxyServer") as string;
                if (current == Ours)
                {
                    key.SetValue("ProxyEnable", backup.ProxyEnable ?? 0, RegistryValueKind.DWord);
                    SetOrDelete(key, "ProxyServer", backup.ProxyServer);
                    SetOrDelete(key, "ProxyOverride", backup.ProxyOverride);
                    SetOrDelete(key, "AutoConfigURL", backup.AutoConfigURL);
                    Notify();
                }
            }
        }
        finally
        {
            try { File.Delete(BackupFile); } catch { /* уже нет */ }
        }
    }

    /// <summary>Вызывается при запуске: если в прошлый раз прокси остался включённым, откатываем.</summary>
    public static void RestoreIfStale() => Restore();

    private static void SetOrDelete(RegistryKey key, string name, string? value)
    {
        if (value is null) key.DeleteValue(name, throwOnMissingValue: false);
        else key.SetValue(name, value, RegistryValueKind.String);
    }

    [DllImport("wininet.dll", SetLastError = true)]
    private static extern bool InternetSetOption(IntPtr hInternet, int option, IntPtr buffer, int length);

    private static void Notify()
    {
        InternetSetOption(IntPtr.Zero, 39, IntPtr.Zero, 0); // INTERNET_OPTION_SETTINGS_CHANGED
        InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0); // INTERNET_OPTION_REFRESH
    }
}
