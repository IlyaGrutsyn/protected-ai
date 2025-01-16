import paramiko
import re
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_community.chat_models.gigachat import GigaChat
from auth import BASIC_AUTHORIZATION_KEY
import getpass

# Авторизация в GigaChat
llm = GigaChat(
    credentials=BASIC_AUTHORIZATION_KEY,
    scope="GIGACHAT_API_PERS",
    model="GigaChat",
    verify_ssl_certs=False,
    streaming=False,
)

messages = [
    SystemMessage(content="Ты в роли защитника веб-сервиса по вопросам информационной безопасности.")
]

# Сопоставление технологий и пакетов
TECH_TO_PACKAGE = {
    "SSL": "openssl",
    "TLS": "openssl",
    "аутентификация": "libpam-google-authenticator",
    "авторизация": "libpam-google-authenticator",
    "логирование": "rsyslog",
    "SQL инъекции": "sqlite3",
    "XSS": "modsecurity-crs",
    "DDoS": "fail2ban",
    "CDN": "dnsutils",
    "обновление": "unattended-upgrades",
    "патчинг": "apt",
    "безопасность конфигураций": "apparmor",
    "реагирование на инциденты": "logwatch",
    "параметризованные запросы": "sqlite3",
    "фильтрация данных": "modsecurity"
}


def get_security_recommendations():
    user_input = "Какие технологии необходимы для защиты данного веб-сервиса?"
    messages.append(HumanMessage(content=user_input))
    response = llm.invoke(messages)
    messages.append(response)
    return response.content


def extract_technologies(recommendations):
    found_technologies = []
    for keyword in TECH_TO_PACKAGE.keys():
        if re.search(rf"\b{keyword}\b", recommendations, re.IGNORECASE):
            found_technologies.append(keyword)
    return found_technologies


def run_command(ssh, command, password):
    """Выполняет команду через SSH с правами sudo, возвращает вывод и ошибки."""
    stdin, stdout, stderr = ssh.exec_command(f"echo {password} | sudo -S {command}")
    output = stdout.read().decode().strip()
    error = stderr.read().decode().strip()
    return output, error


def prepare_system(ssh, password):
    print("\n🔄 Подготовка системы...")
    commands = [
        "sudo killall apt apt-get dpkg 2>/dev/null",  # Завершаем все процессы, связанные с apt/dpkg
        "sudo rm -rf /var/lib/dpkg/lock-frontend /var/cache/apt/archives/lock /var/lib/apt/lists/lock",  # Удаляем блокировки
        "sudo dpkg --configure -a",  # Завершаем конфигурацию, если что-то осталось
        "sudo apt-get update"  # Обновляем систему
    ]
    
    for command in commands:
        output, error = run_command(ssh, command, password)
        if error:
            print(f"⚠️ Ошибка при выполнении команды '{command}': {error}")
        else:
            print(f"✅ Успешно: {command}")


def check_sudo(ssh, password):
    """Проверяет, есть ли права sudo у пользователя."""
    output, error = run_command(ssh, "sudo -n true", password)
    if "password is required" in error.lower():
        print("❌ Требуются права sudo для выполнения команды.")
        return False
    return True


def package_exists(ssh, package, password):
    """Проверяет, доступен ли пакет в репозиториях."""
    output, error = run_command(ssh, f"apt-cache policy {package}", password)
    if "Installed: (none)" in output or "Candidate: (none)" in output:
        return False
    return True


def install_technologies_over_ssh(ip, username, password, technologies):
    """Подключается к серверу по SSH, обновляет систему и устанавливает технологии."""
    installed_technologies = []
    failed_technologies = []

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(ip, username=username, password=password)
    except Exception as e:
        print(f"❌ Ошибка подключения: {e}")
        return installed_technologies, failed_technologies

    if not check_sudo(ssh, password):
        print("🔒 Убедитесь, что пользователь имеет права sudo.")
        return installed_technologies, failed_technologies

    print("\n🔄 Подготовка системы...")
    prepare_system(ssh, password)

    print("\n📦 Установка технологий:")
    for tech in technologies:
        package = TECH_TO_PACKAGE.get(tech)
        if not package:
            print(f"⚠️ Пакет для '{tech}' не найден.")
            failed_technologies.append(tech)
            continue

        if not package_exists(ssh, package, password):
            print(f"⚠️ Пакет '{package}' отсутствует в репозиториях.")
            failed_technologies.append(tech)
            continue

        print(f"⬇️ Устанавливаю '{tech}' ({package})...")
        install_output, install_error = run_command(
            ssh, f"DEBIAN_FRONTEND=noninteractive apt-get install -y {package}", password
        )

        if install_error:
            print(f"❌ Ошибка установки {package}: {install_error}")
            failed_technologies.append(tech)
        else:
            print(f"✅ Успешно установлено: {package}")
            if package not in installed_technologies:
                installed_technologies.append(package)

    ssh.close()
    return installed_technologies, failed_technologies


def log_results(installed, failed):
    with open("install_log.txt", "w", encoding="utf-8") as log_file:
        log_file.write("Установленные технологии:\n")
        log_file.write(", ".join(installed) + "\n\n")
        log_file.write("Не удалось установить:\n")
        for tech in failed:
            reason = "Отсутствует в репозиториях" if tech in TECH_TO_PACKAGE.values() else "Требуется ручная настройка"
            log_file.write(f"{tech}: {reason}\n")
    print("Отчет сохранен в install_log.txt")


def main():
    # Шаг 1: Получить рекомендации от GigaChat
    recommendations = get_security_recommendations()
    print("\nРекомендации по безопасности:\n", recommendations)

    # Шаг 2: Выделить технологии для установки
    technologies = extract_technologies(recommendations)
    if not technologies:
        print("⚠️ Не найдено технологий для установки. Завершаю.")
        return

    print("\nТехнологии для установки и их пакеты:")
    for tech in technologies:
        package = TECH_TO_PACKAGE.get(tech, "Не найдено")
        print(f" - {tech}: {package}")

    # Шаг 3: Установка через SSH
    ip = input("\nВведите IP-адрес сервера: ")
    username = input("Введите имя пользователя: ")
    password = getpass.getpass("Введите пароль: ")

    installed, failed = install_technologies_over_ssh(ip, username, password, technologies)

    # Шаг 4: Логирование и отчет
    log_results(installed, failed)

    print("\n📄 Итоговый отчёт:")
    print(f"✅ Установленные пакеты: {', '.join(installed) if installed else 'Нет'}")
    print(f"❌ Не удалось установить: {', '.join(failed) if failed else 'Нет'}")
    print("\nПодробности сохранены в install_log.txt.")


if __name__ == "__main__":
    main()