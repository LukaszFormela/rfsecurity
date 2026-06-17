<?php
declare(strict_types=1);

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require __DIR__ . '/vendor/autoload.php';

// ─── Load environment variables from .env ─────────────────────────────────────
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();
$dotenv->required(['GMAIL_ADDRESS', 'GMAIL_APP_PASS', 'TURNSTILE_SECRET'])->notEmpty();

define('GMAIL_ADDRESS',     $_ENV['GMAIL_ADDRESS']);
define('GMAIL_APP_PASS',    $_ENV['GMAIL_APP_PASS']);
define('TURNSTILE_SECRET',  $_ENV['TURNSTILE_SECRET']);
// ──────────────────────────────────────────────────────────────────────────────

// Only allow POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit('Method not allowed');
}

// Honeypot: legitimate browsers leave this blank; bots fill it in
if (!empty($_POST['website'])) {
    // Silently succeed so bots don't know they were caught
    http_response_code(200);
    exit('OK');
}

// ─── Cloudflare Turnstile verification ───────────────────────────────────────
$turnstileToken = trim($_POST['cf-turnstile-response'] ?? '');

if ($turnstileToken === '') {
    http_response_code(400);
    exit('Brakuje weryfikacji CAPTCHA.');
}

$verifyResponse = file_get_contents('https://challenges.cloudflare.com/turnstile/v0/siteverify', false,
    stream_context_create([
        'http' => [
            'method'  => 'POST',
            'header'  => 'Content-Type: application/x-www-form-urlencoded',
            'content' => http_build_query([
                'secret'   => TURNSTILE_SECRET,
                'response' => $turnstileToken,
                'remoteip' => $_SERVER['REMOTE_ADDR'] ?? '',
            ]),
        ],
    ])
);

if ($verifyResponse === false) {
    http_response_code(503);
    exit('Nie można zweryfikować CAPTCHA. Spróbuj ponownie.');
}

$verifyData = json_decode($verifyResponse, true);
if (empty($verifyData['success'])) {
    http_response_code(400);
    exit('Weryfikacja CAPTCHA nie powiodła się. Odśwież stronę i spróbuj ponownie.');
}

// ─── Sanitise & validate input ───────────────────────────────────────────────
$name    = trim($_POST['name']    ?? '');
$email   = trim($_POST['email']   ?? '');
$phone   = trim($_POST['phone']   ?? '');
$message = trim($_POST['message'] ?? '');

if ($name === '' || $email === '' || $message === '') {
    http_response_code(400);
    exit('Wypełnij wymagane pola: imię, e-mail i wiadomość.');
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    exit('Podany adres e-mail jest nieprawidłowy.');
}

// Length guards to prevent oversized payloads
if (mb_strlen($name) > 100 || mb_strlen($email) > 254 || mb_strlen($message) > 4000) {
    http_response_code(400);
    exit('Dane są za długie.');
}

// ─── Send email via Gmail SMTP ────────────────────────────────────────────────
$mail = new PHPMailer(true);

try {
    $mail->isSMTP();
    $mail->Host       = 'smtp.gmail.com';
    $mail->SMTPAuth   = true;
    $mail->Username   = GMAIL_ADDRESS;
    $mail->Password   = GMAIL_APP_PASS;
    $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
    $mail->Port       = 465;
    $mail->CharSet    = PHPMailer::CHARSET_UTF8;

    // From: your own address (required by Gmail; see Reply-To for the sender)
    $mail->setFrom(GMAIL_ADDRESS, 'RF Security – Formularz kontaktowy');
    $mail->addAddress(GMAIL_ADDRESS);

    // Reply-To lets you hit "Reply" and write back directly to the visitor
    $mail->addReplyTo($email, $name);

    $mail->Subject = "Nowa wiadomość z formularza – {$name}";
    $mail->Body =
        "Imię i nazwisko: {$name}\n" .
        "E-mail: {$email}\n" .
        "Telefon: " . ($phone !== '' ? $phone : '(nie podano)') . "\n\n" .
        "Wiadomość:\n{$message}\n";

    $mail->send();

    http_response_code(200);
    exit('OK');
} catch (Exception $e) {
    // Log internally but don't expose details to the client
    error_log('PHPMailer error: ' . $mail->ErrorInfo);
    http_response_code(500);
    exit('Nie udało się wysłać wiadomości. Zadzwoń do nas bezpośrednio lub napisz na e-mail.');
}
