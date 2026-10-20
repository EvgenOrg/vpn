using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using Microsoft.Web.WebView2.Core;
using SecurityVpn.Services;

namespace SecurityVpn;

public partial class MainWindow : Window
{
    private const string Origin = "https://app.local/";

#if DEBUG
    private const bool DebugBuild = true;
#else
    private const bool DebugBuild = false;
#endif

    private WebBridge? _bridge;

    public MainWindow()
    {
        InitializeComponent();
        SourceInitialized += (_, _) => RoundCorners();
        Loaded += async (_, _) => await InitWebAsync();
        Closed += (_, _) => _bridge?.Shutdown();
    }

    private async Task InitWebAsync()
    {
        try
        {
            var env = await CoreWebView2Environment.CreateAsync(null, Path.Combine(AppPaths.DataDir, "webview"));
            await Web.EnsureCoreWebView2Async(env);
        }
        catch (WebView2RuntimeNotFoundException)
        {
            MessageBox.Show(
                "Не найден компонент Microsoft Edge WebView2 Runtime.\nУстановите его (microsoft.com/edge/webview2) и запустите приложение снова.",
                "Security VPN", MessageBoxButton.OK, MessageBoxImage.Error);
            Close();
            return;
        }

        if (!Directory.Exists(AppPaths.WebDir))
        {
            MessageBox.Show("Не найдена папка Web с интерфейсом: " + AppPaths.WebDir, "Security VPN", MessageBoxButton.OK, MessageBoxImage.Error);
            Close();
            return;
        }

        var core = Web.CoreWebView2;
        core.Settings.AreDevToolsEnabled = DebugBuild;
        core.Settings.AreBrowserAcceleratorKeysEnabled = DebugBuild;
        core.Settings.AreDefaultContextMenusEnabled = false;
        core.Settings.IsStatusBarEnabled = false;
        core.Settings.IsZoomControlEnabled = false;
        core.Settings.IsPasswordAutosaveEnabled = false;
        core.Settings.IsGeneralAutofillEnabled = false;

        // Интерфейс грузится из локальной папки Web через виртуальный адрес, наружу страница никуда не ходит
        core.SetVirtualHostNameToFolderMapping("app.local", AppPaths.WebDir, CoreWebView2HostResourceAccessKind.Allow);
        core.NavigationStarting += (_, e) =>
        {
            if (!e.Uri.StartsWith(Origin, StringComparison.OrdinalIgnoreCase)) e.Cancel = true;
        };
        core.NewWindowRequested += (_, e) => e.Handled = true;

        var bridge = new WebBridge(core, this);
        _bridge = bridge;
        core.WebMessageReceived += (_, e) =>
        {
            if (e.Source.StartsWith(Origin, StringComparison.OrdinalIgnoreCase))
                bridge.OnMessage(e.WebMessageAsJson);
        };

        // dotnet run -- --demo: окно с демо-интерфейсом без сервера и ядра (для проверки внешнего вида)
        var demo = Environment.GetCommandLineArgs().Contains("--demo", StringComparer.OrdinalIgnoreCase);
        core.Navigate(Origin + "index.html" + (demo ? "?demo=1" : ""));
    }

    // Скруглённые углы окна в Windows 11 (в Windows 10 вызов просто ничего не делает)
    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    private void RoundCorners()
    {
        try
        {
            var handle = new WindowInteropHelper(this).Handle;
            var round = 2; // DWMWCP_ROUND
            DwmSetWindowAttribute(handle, 33, ref round, sizeof(int)); // DWMWA_WINDOW_CORNER_PREFERENCE
        }
        catch { /* косметика */ }
    }
}
