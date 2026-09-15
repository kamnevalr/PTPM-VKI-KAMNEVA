import re
import logging


BLACKLIST = [
    "admin", "root", "superuser", "administrator", "moderator",
    "test", "user", "guest", "support", "help"
]

PHONE_PATTERN = re.compile(r"^\+?\d{1,3}-\d{3}-\d{3}-\d{4}$")
EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
LOGIN_STRING_PATTERN = re.compile(r"^[a-zA-Z0-9_]+$")

CYRILLIC_UPPER = set("АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ")
CYRILLIC_LOWER = set("абвгдеёжзийклмнопрстуфхцчшщъыьэюя")
DIGITS = set("0123456789")
SPECIAL_CHARS = set("!@#$%^&*()-_+=<>?/.,;:'\"{}[]|\\`~")


def mask_password(password: str) -> str:
    if not password:
        return ""
    if len(password) <= 2:
        return password[0] + "*"
    return password[0] + "*" * (len(password) - 2) + password[-1]


def validate_login(login: str) -> tuple[bool, str]:
    if not login or not login.strip():
        return False, "Логин не может быть пустым"

    login = login.strip()

    if PHONE_PATTERN.match(login):
        logging.debug(f"Логин '{login}' распознан как телефон")
        return True, ""

    if EMAIL_PATTERN.match(login):
        logging.debug(f"Логин '{login}' распознан как email")
        return True, ""

    if len(login) < 5:
        return False, f"Логин слишком короткий ({len(login)} символов). Минимум 5 символов"

    if not LOGIN_STRING_PATTERN.match(login):
        return False, "Логин может содержать только латинские буквы, цифры и знак подчёркивания"

    if login.lower() in BLACKLIST:
        return False, f"Логин '{login}' запрещён (чёрный список)"

    logging.debug(f"Логин '{login}' прошёл валидацию как строка")
    return True, ""


def validate_password(password: str) -> tuple[bool, str]:
    if not password:
        return False, "Пароль не может быть пустым"

    if len(password) < 7:
        return False, f"Пароль слишком короткий ({len(password)} символов). Минимум 7 символов"

    has_cyrillic_upper = False
    has_cyrillic_lower = False
    has_digit = False
    has_special = False

    for char in password:
        if char in CYRILLIC_UPPER:
            has_cyrillic_upper = True
        elif char in CYRILLIC_LOWER:
            has_cyrillic_lower = True
        elif char in DIGITS:
            has_digit = True
        elif char in SPECIAL_CHARS:
            has_special = True

    missing = []
    if not has_cyrillic_upper:
        missing.append("заглавную кириллическую букву")
    if not has_cyrillic_lower:
        missing.append("строчную кириллическую букву")
    if not has_digit:
        missing.append("цифру")
    if not has_special:
        missing.append("спецсимвол")

    if missing:
        return False, f"Пароль должен содержать: {', '.join(missing)}"

    logging.debug("Пароль прошёл все проверки сложности")
    return True, ""


def validate_registration(login: str, password: str, password_confirm: str) -> tuple[bool, str]:
    logging.info(f"Начало валидации регистрации для логина: '{login}'")

    login_valid, login_error = validate_login(login)
    if not login_valid:
        logging.warning(f"Валидация логина не пройдена: {login_error}")
        return False, login_error

    password_valid, password_error = validate_password(password)
    if not password_valid:
        logging.warning(f"Валидация пароля не пройдена: {password_error}")
        return False, password_error

    if password != password_confirm:
        logging.warning("Пароль и подтверждение не совпадают")
        return False, "Пароль и подтверждение пароля не совпадают"

    logging.info(f"Регистрация для логина '{login}' успешно завершена")
    return True, ""


if __name__ == "__main__":
    test_cases = [
        ("admin", "Passw0rd!", "Passw0rd!"),
        ("+7-999-123-4567", "Пароль123!", "Пароль123!"),
        ("user@email.com", "Тест1234!", "Тест1234!"),
        ("test_user", "短い", "短い"),
        ("ab", "ValidPass1!", "ValidPass1!"),
        ("good_login", "password123", "password123"),
        ("valid_user", "Кириллица1!", "Кириллица1!"),
        ("valid_user2", "Кириллица1!", "Кириллица2!"),
    ]

    for login, password, confirm in test_cases:
        result, message = validate_registration(login, password, confirm)
        masked = mask_password(password)
        print(f"Login: {login}, Password: {masked}, Result: {result}, Message: {message}")
