#!/usr/bin/env php
<?php
declare(strict_types=1);

/*
 * Синхронизация пользователей из базы в конфиг Xray.
 * Запускается от root по таймеру systemd (securityvpn-sync.timer) каждые ~10 секунд.
 *
 *   php sync-xray.php             применить изменения
 *   php sync-xray.php --dry-run   только показать конфиг, ничего не менять
 *
 * Xray перезапускается только если список пользователей действительно изменился.
 */

if (PHP_SAPI !== 'cli') {
    exit(1);
}

$dryRun = in_array('--dry-run', $argv, true);
$confDir = getenv('SVPN_CONF_DIR') ?: '/etc/securityvpn';
$xrayConfig = getenv('SVPN_XRAY_CONFIG') ?: '/usr/local/etc/xray/config.json';

if (!$dryRun && function_exists('posix_geteuid') && posix_geteuid() !== 0) {
    fwrite(STDERR, "Запускайте от root\n");
    exit(1);
}

function read_json(string $path): array
{
    $raw = @file_get_contents($path);
    $data = $raw === false ? null : json_decode($raw, true);
    if (!is_array($data)) {
        fwrite(STDERR, "Не удалось прочитать $path\n");
        exit(1);
    }
    return $data;
}

function run(string $cmd): int
{
    exec($cmd . ' 2>&1', $out, $code);
    if ($code !== 0) {
        fwrite(STDERR, implode("\n", $out) . "\n");
    }
    return $code;
}

$api = read_json("$confDir/api.json");
$srv = read_json("$confDir/server.json");
$rl = read_json("$confDir/reality.json");

try {
    $pdo = new PDO(
        sprintf('mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4', $api['db_host'] ?? '127.0.0.1', $api['db_port'] ?? 3306, $api['db_name']),
        $api['db_user'],
        $api['db_pass'],
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]
    );
} catch (PDOException $e) {
    fwrite(STDERR, 'База недоступна: ' . $e->getMessage() . "\n");
    exit(1);
}

$flow = $srv['flow'] ?? 'xtls-rprx-vision';

// Один «пустой» клиент всегда есть в конфиге, чтобы Xray стартовал, даже если пользователей ещё нет
$clients = [['id' => $rl['placeholderUuid'], 'flow' => $flow, 'email' => 'placeholder@svpn']];
foreach ($pdo->query('SELECT username, uuid FROM users WHERE is_active = 1 ORDER BY id') as $row) {
    $clients[] = ['id' => $row['uuid'], 'flow' => $flow, 'email' => $row['username'] . '@svpn'];
}

$config = [
    'log' => ['loglevel' => 'warning'],
    'inbounds' => [[
        'listen' => '0.0.0.0',
        'port' => (int)($srv['port'] ?? 443),
        'protocol' => 'vless',
        'settings' => ['clients' => $clients, 'decryption' => 'none'],
        'streamSettings' => [
            'network' => 'tcp',
            'security' => 'reality',
            'realitySettings' => [
                'show' => false,
                'dest' => $srv['dest'] ?? ($srv['sni'] . ':443'), // сайт-«маска», куда Reality отправляет чужие запросы
                'xver' => 0,
                'serverNames' => [$srv['sni']],
                'privateKey' => $rl['privateKey'],
                'shortIds' => [$srv['shortId']],
            ],
        ],
        'sniffing' => ['enabled' => true, 'destOverride' => ['http', 'tls', 'quic']],
    ]],
    'outbounds' => [
        ['protocol' => 'freedom', 'tag' => 'direct'],
        ['protocol' => 'blackhole', 'tag' => 'block'],
    ],
];

$json = json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";

if ($dryRun) {
    echo preg_replace('/("privateKey": ")[^"]+/', '$1***', $json);
    exit(0);
}

$current = is_file($xrayConfig) ? (string)file_get_contents($xrayConfig) : '';
$changed = $current !== $json;

if ($changed) {
    $tmp = $xrayConfig . '.new';
    file_put_contents($tmp, $json);
    chmod($tmp, 0600);

    if (run('/usr/local/bin/xray run -test -config ' . escapeshellarg($tmp)) !== 0) {
        unlink($tmp);
        fwrite(STDERR, "Новый конфиг не прошёл проверку, оставляю прежний\n");
        exit(1);
    }

    // Xray работает от непривилегированного пользователя — даём ему право читать (и только ему)
    $user = trim((string)shell_exec('systemctl show -p User --value xray 2>/dev/null'));
    if ($user !== '' && $user !== 'root') {
        $group = trim((string)shell_exec('id -gn ' . escapeshellarg($user) . ' 2>/dev/null'));
        if ($group !== '') {
            chgrp($tmp, $group);
            chmod($tmp, 0640);
        }
    }
    rename($tmp, $xrayConfig);
    run('systemctl enable xray');
    run('systemctl restart xray');
    echo 'Xray: конфиг обновлён, пользователей: ' . (count($clients) - 1) . "\n";
} elseif (run('systemctl is-active --quiet xray') !== 0) {
    run('systemctl restart xray');
}

// Все активные пользователи теперь есть в конфиге
$pdo->exec('UPDATE users SET synced = 1 WHERE is_active = 1 AND synced = 0');

// Уборка: просроченные токены и старые записи о попытках входа
$pdo->exec('DELETE FROM tokens WHERE expires_at < NOW()');
$pdo->exec('DELETE FROM attempts WHERE created_at < (NOW() - INTERVAL 1 DAY)');
