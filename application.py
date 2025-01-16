import paramiko
import time
import re
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_community.chat_models.gigachat import GigaChat
from auth import BASIC_AUTHORIZATION_KEY
from paramiko.ssh_exception import AuthenticationException
from flask import Flask, render_template, request

# Flask приложение
app = Flask(__name__)

# Авторизация в GigaChat
llm = GigaChat(
    credentials=BASIC_AUTHORIZATION_KEY,
    scope="GIGACHAT_API_PERS",
    model="GigaChat",
    verify_ssl_certs=False,
    streaming=False,
)

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
    messages = [SystemMessage(content="Ты в роли защитника веб-сервиса по вопросам информационной безопасности.")]
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
    messages = []
    messages.append("🔄 Подготовка системы...")
    commands = [
        "sudo killall apt apt-get dpkg 2>/dev/null",  
        "sudo rm -rf /var/lib/dpkg/lock-frontend /var/cache/apt/archives/lock /var/lib/apt/lists/lock",  
        "sudo dpkg --configure -a",  
        "sudo apt-get update"  
    ]
    
    for command in commands:
        output, error = run_command(ssh, command, password)
        if error:
            messages.append(f"⚠️ Ошибка при выполнении команды '{command}': {error}")
        else:
            messages.append(f"✅ Успешно: {command}")
    return messages

def install_technologies_over_ssh(ip, username, password, technologies):
    """Подключается к серверу по SSH, обновляет систему и устанавливает технологии."""
    installed_technologies = []
    failed_technologies = []
    messages = []

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Пытаемся подключиться с неверным паролем для диагностики
        ssh.connect(ip, username=username, password=password)
        # Если подключение прошло успешно, выполняем команду для проверки
        output, error = run_command(ssh, "echo Проверка аутентификации", password)
        if error:
            messages.append(f"⚠️ Ошибка при выполнении команды 'echo Проверка аутентификации': {error}")
            return installed_technologies, failed_technologies, messages

        messages.append(f"✅ Успешно подключено и аутентифицировано с {username}@{ip}")
        
        # Добавляем задержку перед следующим действием
        time.sleep(2) 

    except AuthenticationException as e:
        messages.append(f"❌ Ошибка аутентификации: Неверный пароль для {username}@{ip}")
        return installed_technologies, failed_technologies, messages
    except paramiko.SSHException as e:
        messages.append(f"❌ Ошибка SSH-соединения: {e}")
        return installed_technologies, failed_technologies, messages
    except Exception as e:
        messages.append(f"❌ Неизвестная ошибка: {e}")
        return installed_technologies, failed_technologies, messages

    # Логика работы с системными командами и установкой технологий...
    for tech in technologies:
        package = TECH_TO_PACKAGE.get(tech)
        if not package:
            messages.append(f"⚠️ Пакет для '{tech}' не найден.")
            failed_technologies.append(tech)
            continue

        # Проверяем доступность пакета
        output, error = run_command(ssh, f"apt-cache policy {package}", password)
        if "Installed: (none)" in output or "Candidate: (none)" in output:
            messages.append(f"⚠️ Пакет '{package}' отсутствует в репозиториях.")
            failed_technologies.append(tech)
            continue

        messages.append(f"⬇️ Устанавливаю '{tech}' ({package})...")
        install_output, install_error = run_command(
            ssh, f"DEBIAN_FRONTEND=noninteractive apt-get install -y {package}", password
        )

        if install_error:
            messages.append(f"❌ Ошибка установки {package}: {install_error}")
            failed_technologies.append(tech)
        else:
            messages.append(f"✅ Успешно установлено: {package}")
            installed_technologies.append(tech)
        
        # Добавляем небольшую задержку между выводами
        time.sleep(2)

    ssh.close()
    return installed_technologies, failed_technologies, messages


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')


@app.route('/run_script', methods=['POST'])
def run_script():
    ip = request.form['ip']
    username = request.form['username']
    password = request.form['password']

    # Получаем рекомендации по безопасности
    recommendations = get_security_recommendations()

    # Извлекаем технологии
    technologies = extract_technologies(recommendations)

    if not technologies:
        return render_template('index.html', message="Не найдено технологий для установки.", messages=[])

    # Устанавливаем технологии через SSH
    installed, failed, messages = install_technologies_over_ssh(ip, username, password, technologies)

    if not messages:
        messages = []  


    recommendations_list = []
    temp_s = ''
    index = 1  

    for i in range(len(recommendations)):
        if recommendations[i] in '1234567890' and recommendations[i + 1] == '.':
            if temp_s.strip(): 
                recommendations_list.append(f"{index}. {temp_s.strip()}")
                index += 1
            temp_s = ''
        else:
            temp_s += recommendations[i]

    # Добавим последний элемент, если он есть
    if temp_s.strip():
        recommendations_list.append(f"{index}. {temp_s.strip()}")   


    return render_template('index.html', messages=messages, recommendations=recommendations_list, installed=installed, failed=failed)



if __name__ == '__main__':
    app.run(debug=True)
