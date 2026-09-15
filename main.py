import logging
import sys
import os

from validator import validate_registration, mask_password


log_format = "%(asctime)s | [%(levelname)-7s] | %(message)s"
date_format = "%Y-%m-%d %H:%M:%S"


def setup_logging():
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    os.makedirs(log_dir, exist_ok=True)

    log_file = os.path.join(log_dir, "file_txt.log")

    logging.basicConfig(
        level=logging.DEBUG,
        format=log_format,
        datefmt=date_format,
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_file, encoding="utf-8")
        ]
    )


def register_user(login: str, password: str, password_confirm: str) -> tuple[bool, str]:
    logging.info(f"Запрос на регистрацию. Логин: '{login}', Пароль: '{mask_password(password)}'")

    try:
        success, message = validate_registration(login, password, password_confirm)

        if success:
            logging.info(f"Регистрация успешна. Логин: '{login}'")
        else:
            logging.warning(f"Регистрация не удалась. Логин: '{login}', Причина: {message}")

        return success, message

    except Exception as ex:
        logging.error(f"Непредвиденная ошибка при регистрации для логина '{login}'")
        logging.exception("Детали ошибки:")
        return False, "Внутренняя ошибка сервера"


def main():
    setup_logging()
    logging.info("Приложение запущено")
    logging.info("Логгер успешно сконфигурирован")

    print("=== Система регистрации пользователей ===\n")

    test_cases = [
        ("admin", "Passw0rd!", "Passw0rd!"),
        ("+7-999-123-4567", "Пароль123!", "Пароль123!"),
        ("user@email.com", "Тест1234!", "Тест1234!"),
        ("test_user", "абвг123!", "абвг123!"),
        ("ab", "ValidPass1!", "ValidPass1!"),
        ("good_login", "password123", "password123"),
        ("valid_user", "Кириллица1!", "Кириллица1!"),
        ("valid_user2", "Кириллица1!", "Кириллица2!"),
        ("", "Passw0rd!", "Passw0rd!"),
        ("regular_user", "абвг123", "абвг123"),
    ]

    for login, password, confirm in test_cases:
        success, message = register_user(login, password, confirm)
        status = "OK" if success else "FAIL"
        print(f"[{status}] Login: '{login}', Password: '{mask_password(password)}' -> {message}")

    logging.info("Приложение завершено работу")


if __name__ == "__main__":
    main()
