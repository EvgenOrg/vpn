<?php
declare(strict_types=1);

require __DIR__ . '/../src/bootstrap.php';

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$path = preg_replace('#^/api#', '', $path);
$path = '/' . trim((string)$path, '/');

try {
    switch ("$method $path") {
        case 'GET /info':
            handle_info();
        case 'POST /register':
            handle_register();
        case 'POST /login':
            handle_login();
        case 'POST /logout':
            handle_logout();
        case 'GET /me':
            handle_me();
        case 'GET /config':
            handle_config();
        case 'POST /password':
            handle_password();
        default:
            fail(404, 'Не найдено');
    }
} catch (PDOException $e) {
    error_log('securityvpn: ошибка базы: ' . $e->getMessage());
    fail(500, 'Внутренняя ошибка сервера');
}

/* ------------------------------------------------------------------ */

/** Публичная информация: название, нужен ли код приглашения, где стоит сервер (для планеты в приложении). */
function handle_info(): never
{
    $srv = conf('server');
    $api = conf('api');
    json_out(200, [
        'name' => $srv['name'] ?? 'Security VPN',
        'inviteRequired' => ($api['invite_code'] ?? '') !== '',
        'location' => $srv['location'] ?? null,
    ]);
}

function handle_register(): never
{
    $ip = client_ip();
    rate_check("register:ip:$ip", 5, 3600);
    rate_hit("register:ip:$ip");

    $data = body();
    $username = trim(str_field($data, 'username'));
    $password = str_field($data, 'password');
    $invite = trim(str_field($data, 'invite'));

    $required = (string)(conf('api')['invite_code'] ?? '');
    if ($required !== '' && !hash_equals($required, $invite)) {
        fail(403, 'Неверный код приглашения');
    }
    validate_username($username);
    validate_password($password);

    $pdo = db();
    try {
        $q = $pdo->prepare('INSERT INTO users (username, password, uuid) VALUES (:u, :p, :uuid)');
        $q->execute([
            'u' => $username,
            'p' => password_hash($password, PASSWORD_DEFAULT),
            'uuid' => uuid_v4(),
        ]);
    } catch (PDOException $e) {
        if ($e->getCode() === '23000') { // нарушение UNIQUE
            fail(409, 'Такой логин уже занят');
        }
        throw $e;
    }
    $userId = (int)$pdo->lastInsertId();

    json_out(201, [
        'token' => issue_token($userId),
        'user' => ['username' => $username],
    ]);
}

function handle_login(): never
{
    $ip = client_ip();
    $data = body();
    $username = trim(str_field($data, 'username'));
    $password = str_field($data, 'password');

    $userBucket = 'login:user:' . strtolower(substr($username, 0, 30));
    rate_check("login:ip:$ip", 10, 600);
    rate_check($userBucket, 20, 600);

    if ($username === '' || $password === '') {
        fail(422, 'Введите логин и пароль');
    }

    $q = db()->prepare('SELECT id, username, password, is_active FROM users WHERE username = :u');
    $q->execute(['u' => $username]);
    $user = $q->fetch();

    $ok = password_verify($password, $user ? $user['password'] : SVPN_DUMMY_HASH);
    if (!$user || !$ok) {
        rate_hit("login:ip:$ip");
        rate_hit($userBucket);
        fail(401, 'Неверный логин или пароль');
    }
    if (!(int)$user['is_active']) {
        fail(403, 'Аккаунт отключён');
    }

    if (password_needs_rehash($user['password'], PASSWORD_DEFAULT)) {
        db()->prepare('UPDATE users SET password = :p WHERE id = :id')
            ->execute(['p' => password_hash($password, PASSWORD_DEFAULT), 'id' => $user['id']]);
    }

    json_out(200, [
        'token' => issue_token((int)$user['id']),
        'user' => ['username' => $user['username']],
    ]);
}

function handle_logout(): never
{
    $user = auth_user();
    db()->prepare('DELETE FROM tokens WHERE token_hash = :h')->execute(['h' => $user['token_hash']]);
    json_out(200, ['ok' => true]);
}

function handle_me(): never
{
    $user = auth_user();
    json_out(200, ['username' => $user['username'], 'createdAt' => $user['created_at']]);
}

/**
 * Параметры подключения для приложения.
 * 202 = пользователь создан, но сервер ещё не добавил его в Xray (это занимает до ~15 секунд).
 */
function handle_config(): never
{
    $user = auth_user();
    if (!(int)$user['synced']) {
        json_out(202, ['status' => 'pending']);
    }

    $s = conf('server');
    $server = [
        'address' => $s['host'],
        'port' => (int)($s['port'] ?? 443),
        'uuid' => $user['uuid'],
        'flow' => $s['flow'] ?? 'xtls-rprx-vision',
        'sni' => $s['sni'],
        'publicKey' => $s['publicKey'],
        'shortId' => $s['shortId'],
        'fingerprint' => $s['fingerprint'] ?? 'chrome',
        'location' => $s['location'] ?? null,
    ];

    // Ссылка vless:// — пригодится, чтобы проверить сервер в стороннем клиенте (v2rayN, Hiddify и т.п.)
    $link = sprintf(
        'vless://%s@%s:%d?encryption=none&flow=%s&security=reality&sni=%s&fp=%s&pbk=%s&sid=%s&type=tcp#%s',
        $server['uuid'],
        $server['address'],
        $server['port'],
        rawurlencode($server['flow']),
        rawurlencode($server['sni']),
        rawurlencode($server['fingerprint']),
        rawurlencode($server['publicKey']),
        rawurlencode($server['shortId']),
        rawurlencode(($s['name'] ?? 'Security VPN') . '-' . $user['username'])
    );

    json_out(200, ['status' => 'ready', 'server' => $server, 'link' => $link]);
}

/** Смена пароля (аналог profile.php из исходного примера). Остальные сессии завершаются. */
function handle_password(): never
{
    $user = auth_user();
    $data = body();
    $old = str_field($data, 'oldPassword');
    $new = str_field($data, 'newPassword');

    rate_check('password:user:' . $user['id'], 10, 600);

    if ($old === '' || $new === '') {
        fail(422, 'Заполните все поля');
    }
    validate_password($new);
    if ($new === $old) {
        fail(422, 'Новый пароль должен отличаться от старого');
    }

    $pdo = db();
    $q = $pdo->prepare('SELECT password FROM users WHERE id = :id');
    $q->execute(['id' => $user['id']]);
    $row = $q->fetch();
    if (!$row || !password_verify($old, $row['password'])) {
        rate_hit('password:user:' . $user['id']);
        fail(403, 'Старый пароль введён неверно');
    }

    $pdo->prepare('UPDATE users SET password = :p WHERE id = :id')
        ->execute(['p' => password_hash($new, PASSWORD_DEFAULT), 'id' => $user['id']]);
    $pdo->prepare('DELETE FROM tokens WHERE user_id = :id AND token_hash <> :h')
        ->execute(['id' => $user['id'], 'h' => $user['token_hash']]);

    json_out(200, ['ok' => true]);
}
