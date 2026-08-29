<?php
declare(strict_types=1);

/**
 * Signup endpoint — morgemitenand.ch
 *
 * Runs on Infomaniak shared hosting (PHP 8.x). No framework, no dependencies,
 * no database: signups are appended to a JSON Lines file kept OUTSIDE the
 * document root, and a notification mail is sent.
 *
 * Deployment: see docs/DEPLOY.md. $STORE must not be web-reachable.
 */

const ALLOWED_ORIGINS = ['https://morgemitenand.ch', 'https://www.morgemitenand.ch'];
const NOTIFY_TO       = 'hallo@morgemitenand.ch';
const RATE_LIMIT      = 5;    // submissions ...
const RATE_WINDOW     = 3600; // ... per hour, per IP

$STORE   = __DIR__ . '/../../private/signups.jsonl';
$RATEDIR = __DIR__ . '/../../private/rate';

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

function fail(int $code, string $msg): never {
    http_response_code($code);
    echo json_encode(['ok' => false, 'error' => $msg], JSON_UNESCAPED_UNICODE);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    fail(405, 'method_not_allowed');
}

// Same-origin only. Absent Origin/Referer is tolerated: some privacy setups strip them.
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if ($origin !== '' && !in_array($origin, ALLOWED_ORIGINS, true)) {
    fail(403, 'bad_origin');
}

// Honeypot — silently accept so bots do not learn anything.
if (trim((string)($_POST['website'] ?? '')) !== '') {
    echo json_encode(['ok' => true]);
    exit;
}

$name    = trim((string)($_POST['name']   ?? ''));
$email   = trim((string)($_POST['email']  ?? ''));
$tier    = trim((string)($_POST['tier']   ?? ''));
$locale  = trim((string)($_POST['locale'] ?? ''));
$consent = isset($_POST['consent']);

if ($name === '' || mb_strlen($name) > 80)          fail(422, 'bad_name');
if (!filter_var($email, FILTER_VALIDATE_EMAIL))     fail(422, 'bad_email');
if (mb_strlen($email) > 180)                        fail(422, 'bad_email');
if (!$consent)                                      fail(422, 'no_consent');
if (!in_array($locale, ['gsw','de','fr','it','rm'], true))                 $locale = 'gsw';
if (!in_array($tier, ['','halt','talstation','mittelstation','bergstation','gipfel'], true)) $tier = '';

// Strip anything that could forge a header if these values are ever mailed.
$name  = preg_replace('/[\r\n\t]+/', ' ', $name);
$email = preg_replace('/[\r\n]+/', '', $email);

// ---- Rate limit (per IP, file-based) ----
$ip     = (string)($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
$bucket = $RATEDIR . '/' . hash('sha256', $ip . '|morgemitenand') . '.txt';

if (!is_dir($RATEDIR)) { @mkdir($RATEDIR, 0750, true); }

$now  = time();
$hits = [];
if (is_readable($bucket)) {
    $hits = array_filter(
        array_map('intval', explode(',', (string)file_get_contents($bucket))),
        static fn(int $t): bool => $t > $now - RATE_WINDOW
    );
}
if (count($hits) >= RATE_LIMIT) {
    fail(429, 'rate_limited');
}
$hits[] = $now;
@file_put_contents($bucket, implode(',', $hits), LOCK_EX);

// ---- Persist ----
$record = [
    'ts'     => gmdate('c'),
    'name'   => $name,
    'email'  => mb_strtolower($email),
    'tier'   => $tier,
    'locale' => $locale,
    // Truncated hash only: enough to spot abuse, never the raw address.
    'ipref'  => substr(hash('sha256', $ip . '|morgemitenand'), 0, 12),
];

$dir = dirname($STORE);
if (!is_dir($dir)) { @mkdir($dir, 0750, true); }

$line = json_encode($record, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";
if (@file_put_contents($STORE, $line, FILE_APPEND | LOCK_EX) === false) {
    fail(500, 'store_failed');
}

// ---- Notify (best effort; never fails the request) ----
@mail(
    NOTIFY_TO,
    '=?UTF-8?B?' . base64_encode('Neui Aamäldig — morgemitenand.ch') . '?=',
    "Name:   {$name}\nE-Mail: {$email}\nStufe:  " . ($tier ?: '—') . "\nSprooch: {$locale}\nZiit:   {$record['ts']}\n",
    implode("\r\n", [
        'From: Morge mitenand <no-reply@morgemitenand.ch>',
        'Content-Type: text/plain; charset=UTF-8',
        'MIME-Version: 1.0',
    ])
);

echo json_encode(['ok' => true], JSON_UNESCAPED_UNICODE);
