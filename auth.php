<?php
session_start();

$valid_username = "admin";       
$valid_password = "password123"; 
$max_attempts = 3;                
$lockout_time = 5 * 60;           

if (!isset($_SESSION['user_token'])) {
    $_SESSION['user_token'] = bin2hex(random_bytes(32));
}

if (!isset($_SESSION['login_attempts'])) {
    $_SESSION['login_attempts'] = [];
}

$ip = $_SERVER['REMOTE_ADDR'];

function isBlocked($ip, $max_attempts, $lockout_time) {
    if (!isset($_SESSION['login_attempts'][$ip])) {
        return 0;
    }

    $attempts = $_SESSION['login_attempts'][$ip];
    $recent_attempts = array_filter($attempts, function ($time) use ($lockout_time) {
        return $time > time() - $lockout_time;
    });

    $_SESSION['login_attempts'][$ip] = $recent_attempts; 

    if (count($recent_attempts) >= $max_attempts) {
        $remaining_time = $lockout_time - (time() - end($recent_attempts));
        return $remaining_time > 0 ? $remaining_time : 0;
    }

    return 0;
}

function recordFailedAttempt($ip) {
    if (!isset($_SESSION['login_attempts'][$ip])) {
        $_SESSION['login_attempts'][$ip] = [];
    }

    $_SESSION['login_attempts'][$ip][] = time();
}

$blocked_time = isBlocked($ip, $max_attempts, $lockout_time);
if ($blocked_time > 0) {
    die("Ваш IP временно заблокирован. Попробуйте снова через {$blocked_time} секунд.");
}

if (isset($_GET['Login'])) {
    $username = $_GET['username'] ?? '';
    $password = $_GET['password'] ?? '';
    $user_token = $_GET['user_token'] ?? '';

    if ($user_token !== $_SESSION['user_token']) {
        die("Ошибка: недопустимый токен.");
    }

    if ($username === $valid_username && $password === $valid_password) {
        $_SESSION['authenticated'] = true;
        echo "Добро пожаловать, {$username}!";
    } else {
        recordFailedAttempt($ip);
        echo "Неверное имя пользователя или пароль.";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
</head>
<body>
    <form method="GET">
        <label>Имя пользователя:</label><br>
        <input type="text" name="username" required><br>
        <label>Пароль:</label><br>
        <input type="password" name="password" required><br>
        <input type="hidden" name="user_token" value="<?php echo $_SESSION['user_token']; ?>"><br>
        <button type="submit" name="Login">Войти</button>
    </form>
</body>
</html>
