<?php
declare(strict_types=1);

/*
 * Общие функции API: конфиг, база, ответы, лимиты запросов, токены.
 * Подключение к базе повторяет схему из исходных index.php/tasks.php (PDO + prepared statements),
 * но логин и пароль базы лежат не в коде, а в /etc/securityvpn/api.json.
 */

const SVPN_DEFAULT_CONF_DIR = '/etc/securityvpn';
const SVPN_TOKEN_TTL_DAYS = 30;

// Валидный bcrypt-хеш: чтобы вход по несуществующему логину занимал столько же времени, как по существующему
const SVPN_DUMMY_HASH = '$2y$10$aCVWO6Qq6pmpTGxV/4aY5OXarWz5LrndVUvqdo2qFb2thtB37nRQ.';

function json_out(int $status, array $data): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function fail(int $status, string $message, array $extra = []): never
{
    json_out($status, ['error' => $message] + $extra);
}

function conf(string $name): array
{
    static $cache = [];
    if (!isset($cache[$name])) {
        $dir = getenv('SVPN_CONF_DIR') ?: SVPN_DEFAULT_CONF_DIR;
        $raw = @file_get_contents("$dir/$name.json");
        $data = $raw === false ? null : json_decode($raw, true);
        if (!is_array($data)) {
            error_log("securityvpn: не удалось прочитать $dir/$name.json");
            fail(500, 'Сервер не настроен');
        }
        $cache[$name] = $data;
    }
    return $cache[$name];
}

function db(): PDO
{
    static $pdo = null;
    if ($pdo === null) {
        $c = conf('api');
        try {
            $pdo = new PDO(
                sprintf('mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4', $c['db_host'] ?? '127.0.0.1', $c['db_port'] ?? 3306, $c['db_name']),
                $c['db_user'],
                $c['db_pass'],
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES => false,
                ]
            );
        } catch (PDOException $e) {
            error_log('securityvpn: база недоступна: ' . $e->getMessage());
            fail(503, 'Сервис временно недоступен');
        }
    }
    return $pdo;
}

function body(): array
{
    $len = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
    if ($len > 4096) {
        fail(413, 'Слишком большой запрос');
    }
    $raw = file_get_contents('php://input');
    if ($raw === '' || $raw === false) {
        return [];
    }
    $data = json_decode($raw, true);
    if (!is_array($data)) {
        fail(400, 'Некорректный запрос');
    }
    return $data;
}

function str_field(array $data, string $key): string
{
    $v = $data[$key] ?? '';
    return is_string($v) ? $v : '';
}

function client_ip(): string
{
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

/* ---------- ограничение частоты запросов ---------- */

function rate_check(string $bucket, int $max, int $windowSeconds): void
{
    $q = db()->prepare('SELECT COUNT(*) FROM attempts WHERE bucket = :b AND created_at > (NOW() - INTERVAL :s SECOND)');
    $q->bindValue(':b', $bucket);
    $q->bindValue(':s', $windowSeconds, PDO::PARAM_INT);
    $q->execute();
    if ((int)$q->fetchColumn() >= $max) {
        header('Retry-After: ' . $windowSeconds);
        fail(429, 'Слишком много попыток. Подождите немного и повторите.');
    }
}

function rate_hit(string $bucket): void
{
    $q = db()->prepare('INSERT INTO attempts (bucket) VALUES (:b)');
    $q->execute(['b' => $bucket]);
}

/* ---------- проверка данных ---------- */

function validate_username(string $username): void
{
    if (!preg_match('/^[A-Za-z0-9_]{3,30}$/', $username)) {
        fail(422, 'Логин: 3–30 символов, латиница, цифры и _');
    }
}

function validate_password(string $password): void
{
    $len = strlen($password); // bcrypt учитывает только первые 72 байта
    if ($len < 8) {
        fail(422, 'Пароль должен быть не короче 8 символов');
    }
    if ($len > 72) {
        fail(422, 'Пароль слишком длинный (максимум 72 байта)');
    }
}

function uuid_v4(): string
{
    $b = random_bytes(16);
    $b[6] = chr((ord($b[6]) & 0x0f) | 0x40);
    $b[8] = chr((ord($b[8]) & 0x3f) | 0x80);
    $h = bin2hex($b);
    return sprintf('%s-%s-%s-%s-%s', substr($h, 0, 8), substr($h, 8, 4), substr($h, 12, 4), substr($h, 16, 4), substr($h, 20, 12));
}

/* ---------- токены ---------- */

function issue_token(int $userId): string
{
    $token = bin2hex(random_bytes(32));
    $q = db()->prepare(
        'INSERT INTO tokens (user_id, token_hash, expires_at)
         VALUES (:u, :h, NOW() + INTERVAL ' . SVPN_TOKEN_TTL_DAYS . ' DAY)'
    );
    $q->execute(['u' => $userId, 'h' => hash('sha256', $token)]);
    return $token;
}

function bearer_token(): ?string
{
    $h = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
    if (preg_match('/^Bearer\s+([a-f0-9]{64})$/i', $h, $m)) {
        return strtolower($m[1]);
    }
    return null;
}

/** Возвращает строку пользователя по токену или завершает запрос с 401. */
function auth_user(): array
{
    $token = bearer_token();
    if ($token === null) {
        fail(401, 'Требуется вход');
    }
    $hash = hash('sha256', $token);
    $q = db()->prepare(
        'SELECT u.id, u.username, u.uuid, u.is_active, u.synced, u.created_at
         FROM tokens t JOIN users u ON u.id = t.user_id
         WHERE t.token_hash = :h AND t.expires_at > NOW()'
    );
    $q->execute(['h' => $hash]);
    $user = $q->fetch();
    if (!$user) {
        fail(401, 'Сессия истекла, войдите заново');
    }
    if (!(int)$user['is_active']) {
        fail(403, 'Аккаунт отключён');
    }
    db()->prepare('UPDATE tokens SET last_used_at = NOW() WHERE token_hash = :h')->execute(['h' => $hash]);
    $user['token_hash'] = $hash;
    return $user;
}
