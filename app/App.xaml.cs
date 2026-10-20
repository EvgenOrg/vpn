using System.Windows;
using SecurityVpn.Services;

namespace SecurityVpn;

public partial class App : Application
{
    private Mutex? _mutex;

    protected override void OnStartup(StartupEventArgs e)
    {
        // Два экземпляра дрались бы за одни и те же локальные порты ядра
        _mutex = new Mutex(true, @"Local\SecurityVPN.SingleInstance", out var isFirst);
        if (!isFirst)
        {
            MessageBox.Show("Security VPN уже запущен.", "Security VPN", MessageBoxButton.OK, MessageBoxImage.Information);
            Shutdown();
            return;
        }

        // Если прошлый запуск закрылся аварийно, возвращаем системный прокси Windows как было
        try { SystemProxy.RestoreIfStale(); } catch { /* не критично */ }

        DispatcherUnhandledException += (_, _) =>
        {
            try { SystemProxy.Restore(); } catch { /* ничего не поделать */ }
        };

        base.OnStartup(e);
        new MainWindow().Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try { SystemProxy.Restore(); } catch { /* ничего не поделать */ }
        try { _mutex?.ReleaseMutex(); } catch { /* мьютекс мог не принадлежать потоку */ }
        _mutex?.Dispose();
        base.OnExit(e);
    }
}
