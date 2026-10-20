# Скачивает ядро Xray (XTLS/Xray-core) в папку core\ рядом с проектом.
# Запуск (из папки app):  powershell -ExecutionPolicy Bypass -File .\get-xray.ps1

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$core = Join-Path $root 'core'
$tmp  = Join-Path ([IO.Path]::GetTempPath()) ('xray-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null

try {
    $base = 'https://github.com/XTLS/Xray-core/releases/latest/download'
    $zip  = Join-Path $tmp 'xray.zip'

    Write-Host 'Скачиваю Xray-core с github.com/XTLS/Xray-core ...'
    Invoke-WebRequest "$base/Xray-windows-64.zip" -OutFile $zip

    # Проверка контрольной суммы по файлу .dgst из того же релиза
    $expected = $null
    try {
        Invoke-WebRequest "$base/Xray-windows-64.zip.dgst" -OutFile "$zip.dgst"
        $m = Select-String -Path "$zip.dgst" -Pattern '(?i)SHA2?-?256\s*=\s*([0-9a-f]{64})' | Select-Object -First 1
        if ($m) { $expected = $m.Matches[0].Groups[1].Value }
    } catch {
        Write-Warning "Не удалось получить файл контрольной суммы: $($_.Exception.Message)"
    }

    if ($expected) {
        $actual = (Get-FileHash $zip -Algorithm SHA256).Hash
        if ($actual -ne $expected) { throw "Контрольная сумма SHA-256 не совпала (ожидалась $expected, получена $actual). Файл не используется." }
        Write-Host 'Контрольная сумма SHA-256 совпала.'
    } else {
        Write-Warning 'Контрольную сумму проверить не удалось, пропускаю проверку.'
    }

    $unpacked = Join-Path $tmp 'x'
    Expand-Archive -Path $zip -DestinationPath $unpacked -Force

    New-Item -ItemType Directory -Path $core -Force | Out-Null
    foreach ($name in 'xray.exe', 'geoip.dat', 'geosite.dat', 'LICENSE') {
        $src = Join-Path $unpacked $name
        if (Test-Path $src) { Copy-Item $src $core -Force }
    }

    if (-not (Test-Path (Join-Path $core 'xray.exe'))) { throw 'В архиве не нашёлся xray.exe' }

    Write-Host ''
    & (Join-Path $core 'xray.exe') version | Select-Object -First 1
    Write-Host "Готово: $core"
}
finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
