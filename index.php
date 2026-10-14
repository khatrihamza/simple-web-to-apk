<?php
declare(strict_types=1);

/*
 * Website-to-APK Compiler
 * Requires PHP 8+ with cURL and OpenSSL.
 *
 * Set these environment variables on your PHP host:
 * APP_ENCRYPTION_KEY = a long, random secret
 * APP_DATA_FILE      = writable JSON file OUTSIDE public web root
 *
 * Settings page stores GitHub credentials encrypted.
 * Admin key and password are stored as one-way hashes.
 */

ini_set('session.use_strict_mode', '1');
session_set_cookie_params([
    'httponly' => true,
    'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    'samesite' => 'Strict'
]);
session_start();

header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('X-Frame-Options: DENY');

function h($v): string {
    return htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function envv(string $name, string $default = ''): string {
    $v = getenv($name);
    return $v === false ? $default : trim($v);
}

function encryption_key(): string {
    $secret = envv('APP_ENCRYPTION_KEY');
    if (strlen($secret) < 32) {
        throw new RuntimeException(
            'The server APP_ENCRYPTION_KEY must be at least 32 characters.'
        );
    }
    return hash('sha256', $secret, true);
}

function encrypt_secret(string $plain): string {
    $iv = random_bytes(12);
    $tag = '';
    $cipher = openssl_encrypt(
        $plain, 'aes-256-gcm', encryption_key(),
        OPENSSL_RAW_DATA, $iv, $tag
    );
    if ($cipher === false) {
        throw new RuntimeException('Encryption failed.');
    }
    return base64_encode($iv . $tag . $cipher);
}

function decrypt_secret(string $encoded): string {
    $raw = base64_decode($encoded, true);
    if ($raw === false || strlen($raw) < 29) {
        throw new RuntimeException('Saved encrypted settings are invalid.');
    }
    $plain = openssl_decrypt(
        substr($raw, 28), 'aes-256-gcm', encryption_key(),
        OPENSSL_RAW_DATA, substr($raw, 0, 12), substr($raw, 12, 16)
    );
    if ($plain === false) {
        throw new RuntimeException('Cannot decrypt settings. Check APP_ENCRYPTION_KEY.');
    }
    return $plain;
}

function data_file(): string {
    $path = envv('APP_DATA_FILE');

    if ($path === '') {
        // Default is outside the current public folder.
        $path = dirname(__DIR__) . '/webapk-private/store.json';
    }

    $dir = dirname($path);
    if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
        throw new RuntimeException('Cannot create private data folder.');
    }
    if (!is_writable($dir)) {
        throw new RuntimeException('Private data folder is not writable.');
    }
    return $path;
}

function load_data(): array {
    $file = data_file();
    if (!is_file($file)) {
        return ['admin' => null, 'settings' => [], 'jobs' => []];
    }
    $raw = file_get_contents($file);
    $data = json_decode($raw ?: '', true);
    if (!is_array($data)) {
        throw new RuntimeException('Private storage file is invalid.');
    }
    return array_merge(
        ['admin' => null, 'settings' => [], 'jobs' => []],
        $data
    );
}

function save_data(array $data): void {
    $file = data_file();
    $json = json_encode(
        $data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
    );
    if ($json === false ||
        file_put_contents($file, $json, LOCK_EX) === false) {
        throw new RuntimeException('Could not save server-side data.');
    }
    @chmod($file, 0600);
}

function csrf_token(): string {
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function verify_csrf(): void {
    $given = $_POST['csrf'] ?? '';
    if (!is_string($given) ||
        !hash_equals(csrf_token(), $given)) {
        http_response_code(403);
        exit('Invalid form token. Reload the page and try again.');
    }
}

function base_url(): string {
    $configured = rtrim(envv('APP_BASE_URL'), '/');
    if ($configured !== '') {
        return $configured;
    }
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
    $scheme = $https ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? '';
    if ($host === '' || preg_match('/[^a-zA-Z0-9.:\-\[\]]/', $host)) {
        throw new RuntimeException('Set APP_BASE_URL to your public HTTPS website URL.');
    }
    return $scheme . '://' . $host;
}

function valid_website_url(string $url): bool {
    if (strlen($url) > 2000 ||
        !filter_var($url, FILTER_VALIDATE_URL)) {
        return false;
    }

    $p = parse_url($url);
    if (!$p || strtolower($p['scheme'] ?? '') !== 'https' ||
        empty($p['host']) || isset($p['user']) || isset($p['pass'])) {
        return false;
    }

    $host = strtolower(rtrim($p['host'], '.'));
    if ($host === 'localhost' || str_ends_with($host, '.localhost') ||
        str_ends_with($host, '.local')) {
        return false;
    }

    if (filter_var($host, FILTER_VALIDATE_IP)) {
        return (bool)filter_var(
            $host,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        );
    }

    return strpos($host, '.') !== false;
}

function valid_package(string $id): bool {
    return (bool)preg_match(
        '/^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*){2,}$/D',
        $id
    );
}

function github_request(string $url, string $token, ?array $body = null): array {
    if (!function_exists('curl_init')) {
        throw new RuntimeException('PHP cURL is not enabled on this host.');
    }

    $ch = curl_init($url);
    $headers = [
        'Accept: application/vnd.github+json',
        'Authorization: Bearer ' . $token,
        'X-GitHub-Api-Version: 2022-11-28',
        'User-Agent: Website-to-APK-Compiler'
    ];

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 15,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_CUSTOMREQUEST => $body === null ? 'GET' : 'POST',
        CURLOPT_HTTPHEADER => $headers
    ]);

    if ($body !== null) {
        $json = json_encode($body, JSON_UNESCAPED_SLASHES);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $json);
        $headers[] = 'Content-Type: application/json';
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    }

    $response = curl_exec($ch);
    $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);

    if ($response === false) {
        throw new RuntimeException('GitHub connection failed: ' . $error);
    }
    return [$status, $response];
}

function is_logged_in(): bool {
    return !empty($_SESSION['settings_login']);
}

function setting_value(array $data, string $key): string {
    return isset($data['settings'][$key])
        ? decrypt_secret((string)$data['settings'][$key])
        : '';
}

function redirect_to(string $url): never {
    header('Location: ' . $url);
    exit;
}

$error = '';
$message = '';

try {
    // Encryption configuration is required for all requests.
    encryption_key();
    $data = load_data();

    $action = (string)($_GET['action'] ?? '');
    $page = (string)($_GET['page'] ?? 'home');

    /*
     * GitHub Actions callback.
     * It is a POST to index.php?action=callback.
     */
    if ($action === 'callback') {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            exit('POST only');
        }

        $savedSecret = setting_value($data, 'callback_secret');
        $sentSecret = $_SERVER['HTTP_X_BUILD_SECRET'] ?? '';

        if ($savedSecret === '' || $sentSecret === '' ||
            !hash_equals($savedSecret, $sentSecret)) {
            http_response_code(403);
            exit('Forbidden');
        }

        $input = json_decode(file_get_contents('php://input') ?: '', true);
        if (!is_array($input)) {
            http_response_code(400);
            exit('Invalid JSON');
        }

        $id = (string)($input['job_id'] ?? '');
        $status = (string)($input['status'] ?? '');
        if (!preg_match('/^[a-f0-9]{32}$/D', $id) ||
            !isset($data['jobs'][$id]) ||
            !in_array($status, ['running', 'success', 'failure'], true)) {
            http_response_code(400);
            exit('Invalid job');
        }

        $data['jobs'][$id]['status'] = $status;
        $data['jobs'][$id]['updated_at'] = gmdate('c');
        $data['jobs'][$id]['message'] = substr(
            strip_tags((string)($input['message'] ?? '')), 0, 300
        );

        $release = (string)($input['download_url'] ?? '');
        if ($status === 'success') {
            $expectedPrefix = 'https://github.com/';
            if (!str_starts_with($release, $expectedPrefix) ||
                !str_contains($release, '/releases/download/')) {
                http_response_code(400);
                exit('Invalid release URL');
            }
            $data['jobs'][$id]['download_url'] = $release;
        }

        save_data($data);
        header('Content-Type: application/json');
        echo '{"ok":true}';
        exit;
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verify_csrf();
        $postAction = (string)($_POST['do'] ?? '');

        if ($postAction === 'register') {
            if (!empty($data['admin'])) {
                throw new RuntimeException('An administrator is already registered. Use Enter.');
            }

            $key = trim((string)($_POST['admin_key'] ?? ''));
            $password = (string)($_POST['password'] ?? '');

            if (strlen($key) < 12 || strlen($password) < 10) {
                throw new RuntimeException(
                    'Use a key with at least 12 characters and a password with at least 10.'
                );
            }

            $data['admin'] = [
                'key_hash' => password_hash($key, PASSWORD_DEFAULT),
                'password_hash' => password_hash($password, PASSWORD_DEFAULT)
            ];
            save_data($data);
            session_regenerate_id(true);
            $_SESSION['settings_login'] = true;
            $message = 'New admin key registered. Now save GitHub settings below.';
        }

        elseif ($postAction === 'login') {
            $key = (string)($_POST['admin_key'] ?? '');
            $password = (string)($_POST['password'] ?? '');
            $admin = $data['admin'] ?? null;

            if (!$admin ||
                !password_verify($key, $admin['key_hash']) ||
                !password_verify($password, $admin['password_hash'])) {
                throw new RuntimeException('Wrong key or password.');
            }

            session_regenerate_id(true);
            $_SESSION['settings_login'] = true;
            redirect_to('?page=settings');
        }

        elseif ($postAction === 'logout') {
            unset($_SESSION['settings_login']);
            session_regenerate_id(true);
            redirect_to('?page=settings');
        }

        elseif ($postAction === 'save_settings') {
            if (!is_logged_in()) {
                throw new RuntimeException('Enter your admin key and password first.');
            }

            $owner = trim((string)($_POST['github_owner'] ?? ''));
            $repo = trim((string)($_POST['github_repo'] ?? ''));
            $token = trim((string)($_POST['github_token'] ?? ''));
            $callbackSecret = trim((string)($_POST['callback_secret'] ?? ''));

            if (!preg_match('/^[A-Za-z0-9-]{1,39}$/D', $owner) ||
                !preg_match('/^[A-Za-z0-9._-]{1,100}$/D', $repo)) {
                throw new RuntimeException('Check the GitHub owner and repository name.');
            }

            // Blank token/secret fields keep the already saved values.
            if ($token === '') {
                $token = setting_value($data, 'github_token');
            }
            if ($callbackSecret === '') {
                $callbackSecret = setting_value($data, 'callback_secret');
            }

            if (strlen($token) < 20 || strlen($callbackSecret) < 24) {
                throw new RuntimeException(
                    'Enter a GitHub token and callback secret, each sufficiently long.'
                );
            }

            $data['settings']['github_owner'] = encrypt_secret($owner);
            $data['settings']['github_repo'] = encrypt_secret($repo);
            $data['settings']['github_token'] = encrypt_secret($token);
            $data['settings']['callback_secret'] = encrypt_secret($callbackSecret);
            save_data($data);
            $message = 'Settings saved securely on the server.';
        }

        elseif ($postAction === 'build') {
            $url = trim((string)($_POST['website_url'] ?? ''));
            $name = trim((string)($_POST['app_name'] ?? ''));
            $package = trim((string)($_POST['package_id'] ?? ''));

            if (!valid_website_url($url)) {
                throw new RuntimeException('Enter a public HTTPS website URL.');
            }
            if ($name === '' || strlen($name) > 50 ||
                preg_match('/[\x00-\x1F<>]/', $name)) {
                throw new RuntimeException('App name must be 1–50 safe characters.');
            }
            if (!valid_package($package)) {
                throw new RuntimeException(
                    'Package ID must look like com.example.myapp.'
                );
            }

            if (empty($data['settings']['github_token'])) {
                throw new RuntimeException('Open Settings and configure GitHub first.');
            }

            $owner = setting_value($data, 'github_owner');
            $repo = setting_value($data, 'github_repo');
            $token = setting_value($data, 'github_token');

            $id = bin2hex(random_bytes(16));
            $callbackUrl = base_url() . '/index.php?action=callback';

            $data['jobs'][$id] = [
                'id' => $id,
                'app_name' => $name,
                'package_id' => $package,
                'website_url' => $url,
                'status' => 'queued',
                'message' => 'Waiting for GitHub Actions.',
                'created_at' => gmdate('c'),
                'updated_at' => gmdate('c'),
                'download_url' => ''
            ];
            save_data($data);

            $dispatchUrl = 'https://api.github.com/repos/' .
                rawurlencode($owner) . '/' . rawurlencode($repo) .
                '/dispatches';

            [$httpCode, $response] = github_request($dispatchUrl, $token, [
                'event_type' => 'website_to_apk',
                'client_payload' => [
                    'job_id' => $id,
                    'website_url' => $url,
                    'app_name' => $name,
                    'package_id' => $package,
                    'callback_url' => $callbackUrl
                ]
            ]);

            if ($httpCode < 200 || $httpCode >= 300) {
                $data = load_data();
                $data['jobs'][$id]['status'] = 'failure';
                $data['jobs'][$id]['message'] =
                    'GitHub dispatch failed (HTTP ' . $httpCode . '). Check token permissions.';
                save_data($data);
                throw new RuntimeException(
                    'GitHub could not start the build. Check owner, repo, token and token permissions.'
                );
            }

            redirect_to('?page=status&id=' . rawurlencode($id));
        }
    }

    $data = load_data();
} catch (Throwable $e) {
    $error = $e->getMessage();
}

$page = (string)($_GET['page'] ?? 'home');
$id = (string)($_GET['id'] ?? '');
$job = ($id !== '' && isset($data['jobs'][$id])) ? $data['jobs'][$id] : null;

/* Download is only allowed for a successful known job. */
if ($page === 'download') {
    if (!$job || $job['status'] !== 'success' ||
        empty($job['download_url'])) {
        http_response_code(404);
        exit('APK is not ready.');
    }
    $u = (string)$job['download_url'];
    if (!str_starts_with($u, 'https://github.com/') ||
        !str_contains($u, '/releases/download/')) {
        http_response_code(400);
        exit('Invalid download URL.');
    }
    header('Location: ' . $u, true, 302);
    exit;
}

$adminExists = !empty($data['admin']);
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Website to APK Compiler</title>
<style>
:root{color-scheme:dark;--bg:#101114;--panel:#191b20;--line:#30333a;--text:#f4f4f5;--muted:#a6a8b0;--accent:#c9a66b;--bad:#ff7777;--good:#83d9a2}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 system-ui,Arial,sans-serif}
main{max-width:760px;margin:0 auto;padding:24px 16px 60px}.top{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
h1{font-size:25px;margin:10px 0}h2{font-size:20px;margin-top:0}.muted{color:var(--muted);font-size:14px}
nav{display:flex;gap:10px;flex-wrap:wrap;margin:20px 0}a{color:var(--accent)}
nav a,.button{display:inline-block;padding:10px 14px;border-radius:10px;border:1px solid var(--line);text-decoration:none;color:var(--text);background:#22242a}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:20px;margin:16px 0}
label{display:block;font-weight:600;margin:14px 0 6px}input{width:100%;padding:13px;border:1px solid #454852;border-radius:10px;background:#101115;color:white;font:inherit}
button{margin-top:16px;border:0;border-radius:10px;background:var(--accent);color:#171717;font-weight:700;font-size:15px;padding:13px 18px;cursor:pointer;width:100%}
.msg{padding:12px;border-radius:10px;margin:15px 0;background:#292b31}.error{color:var(--bad)}.success{color:var(--good)}
code{overflow-wrap:anywhere}.status{font-weight:700;text-transform:capitalize}
small{color:var(--muted)}hr{border:0;border-top:1px solid var(--line);margin:22px 0}
</style>
</head>
<body><main>
<div class="top">
  <div><div class="muted">BUILD ANDROID APPS</div><h1>Website to APK Compiler</h1></div>
  <div class="muted">PHP + GitHub Actions</div>
</div>
<nav>
  <a href="?page=home">Build APK</a>
  <a href="?page=settings">Settings</a>
</nav>

<?php if ($error !== ''): ?>
<div class="msg error"><?=h($error)?></div>
<?php endif; ?>
<?php if ($message !== ''): ?>
<div class="msg success"><?=h($message)?></div>
<?php endif; ?>

<?php if ($page === 'settings'): ?>
<section class="panel">
<h2>Settings</h2>
<p class="muted">Your admin key and password are checked on the server.</p>

<?php if (!$adminExists): ?>
<form method="post">
<input type="hidden" name="csrf" value="<?=h(csrf_token())?>">
<input type="hidden" name="do" value="register">
<label>Create your new admin key</label>
<input name="admin_key" required minlength="12" autocomplete="off" placeholder="Create a long secret key">
<label>Create a password</label>
<input type="password" name="password" required minlength="10" autocomplete="new-password" placeholder="At least 10 characters">
<button>Register new key</button>
</form>
<?php elseif (!is_logged_in()): ?>
<form method="post">
<input type="hidden" name="csrf" value="<?=h(csrf_token())?>">
<input type="hidden" name="do" value="login">
<label>Existing admin key</label>
<input name="admin_key" required autocomplete="off" placeholder="Enter your existing key">
<label>Password</label>
<input type="password" name="password" required autocomplete="current-password" placeholder="Enter your password">
<button>Enter</button>
</form>
<?php else: ?>
<p class="success">You are signed in to Settings.</p>
<form method="post">
<input type="hidden" name="csrf" value="<?=h(csrf_token())?>">
<input type="hidden" name="do" value="save_settings">
<label>GitHub owner / username</label>
<input name="github_owner" required value="<?=h(isset($data['settings']['github_owner']) ? setting_value($data,'github_owner') : '')?>" placeholder="your-github-username">
<label>GitHub repository</label>
<input name="github_repo" required value="<?=h(isset($data['settings']['github_repo']) ? setting_value($data,'github_repo') : '')?>" placeholder="website-to-apk-compiler">
<label>GitHub token</label>
<input type="password" name="github_token" autocomplete="new-password" placeholder="Paste token (leave blank to keep saved token)">
<label>Callback secret</label>
<input type="password" name="callback_secret" autocomplete="new-password" placeholder="Same value as GitHub Actions secret">
<small>Tokens are encrypted on the server. Leave secret fields blank to keep their saved values.</small>
<button>Save settings</button>
</form>
<hr>
<form method="post">
<input type="hidden" name="csrf" value="<?=h(csrf_token())?>">
<input type="hidden" name="do" value="logout">
<button type="submit">Sign out of Settings</button>
</form>
<?php endif; ?>
</section>

<?php elseif ($page === 'status'): ?>
<section class="panel">
<h2>Build status</h2>
<?php if (!$job): ?>
<p>Job not found. Return to Build APK and submit again.</p>
<?php else: ?>
<p>App: <strong><?=h($job['app_name'])?></strong></p>
<p>Job ID: <code><?=h($job['id'])?></code></p>
<p>Status: <span class="status"><?=h($job['status'])?></span></p>
<p class="muted"><?=h($job['message'] ?? '')?></p>
<?php if ($job['status'] === 'success'): ?>
<a class="button" href="?page=download&id=<?=h($job['id'])?>">Download APK</a>
<?php elseif ($job['status'] === 'queued' || $job['status'] === 'running'): ?>
<p class="muted">This page checks again automatically every 8 seconds.</p>
<meta http-equiv="refresh" content="8">
<?php else: ?>
<p class="muted">The build did not finish successfully. Check the Actions tab in GitHub for the error.</p>
<?php endif; ?>
<?php endif; ?>
</section>

<?php else: ?>
<section class="panel">
<h2>Create your APK</h2>
<p class="muted">Enter a public HTTPS website. GitHub Actions builds the Android app.</p>
<form method="post">
<input type="hidden" name="csrf" value="<?=h(csrf_token())?>">
<input type="hidden" name="do" value="build">
<label>Website URL</label>
<input type="url" name="website_url" required placeholder="https://example.com">
<label>App name</label>
<input name="app_name" required maxlength="50" placeholder="My Website App">
<label>Package ID</label>
<input name="package_id" required pattern="[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*){2,}" placeholder="com.example.myapp">
<button>Start APK build</button>
</form>
</section>
<section class="panel">
<h2>Recent builds</h2>
<?php
$recent = array_values($data['jobs']);
usort($recent, fn($a,$b) => strcmp($b['created_at'] ?? '', $a['created_at'] ?? ''));
foreach (array_slice($recent, 0, 10) as $j):
?>
<p><strong><?=h($j['app_name'])?></strong> — <?=h($j['status'])?>
<br><a href="?page=status&id=<?=h($j['id'])?>">View status</a></p>
<?php endforeach; ?>
<?php if (!$recent): ?><p class="muted">No builds yet.</p><?php endif; ?>
</section>
<?php endif; ?>

<p class="muted">Keep this website private to trusted users. Anyone who can use the build form may consume your GitHub Actions minutes.</p>
</main></body></html>
