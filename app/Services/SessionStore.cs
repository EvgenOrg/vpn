using System.Security.Cryptography;
using System.Text;

namespace SecurityVpn.Services;

/// <summary>Токен входа хранится на диске только в зашифрованном виде (Windows DPAPI, привязка к вашей учётной записи Windows).</summary>
internal static class SessionStore
{
    private static string FilePath => Path.Combine(AppPaths.DataDir, "session.dat");

    public static void Save(string token)
    {
        var data = ProtectedData.Protect(Encoding.UTF8.GetBytes(token), null, DataProtectionScope.CurrentUser);
        File.WriteAllBytes(FilePath, data);
    }

    public static string? Load()
    {
        try
        {
            if (!File.Exists(FilePath)) return null;
            var data = ProtectedData.Unprotect(File.ReadAllBytes(FilePath), null, DataProtectionScope.CurrentUser);
            return Encoding.UTF8.GetString(data);
        }
        catch
        {
            return null; // файл повреждён или из другой учётной записи: просто войдём заново
        }
    }

    public static void Clear()
    {
        try { File.Delete(FilePath); } catch { /* уже нет */ }
    }
}
