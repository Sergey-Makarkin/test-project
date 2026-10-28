# MPortal Email Alerting: редактируемый From

Этот небольшой патч предназначен **только для установленной версии MPortal Email Alerting LIVE v1**, в которой `/admin/alerting` уже содержит SMTP Server / Port, а поле From отключено. Он не повторно устанавливает предыдущие этапы и не меняет Zabbix, проекты, получателей или базу очереди.

## Изменения

- В `/admin/alerting` поле **From (email address)** становится редактируемым. Сохраняется вместе с SMTP host и port.
- В SQLite `mp_alert_smtp` добавляется колонка `smtp_from`, если её нет. Существующие адреса получателей, правила, SMTP host/port и состояние отправки сохраняются; для уже установленной базы начальное значение — `mportal@example.com`.
- Проверка адреса отправителя: один обычный Email-адрес; запрещены управляющие символы, имена вида `Name <email>` и внедрение заголовков.
- LIVE-worker использует настроенный From **и в заголовке письма, и в SMTP MAIL FROM**; новые настройки читает при каждом цикле.
- AUTH и STARTTLS остаются выключенными. Никакое письмо не отправляется во время обновления или сохранения формы.
- `smtp_test_once.py` показывает конфигурацию, а с `--send` отправляет ровно одно тестовое письмо существующему получателю выбранного хоста.

## 1. Перенос

Перенесите через Git содержимое папки `mportal-email-from-edit-v1` в `/home/virp_smmak/mportal/alerting/mportal-email-from-edit-v1`.

## 2. Безопасная установка

```bash
SRC=/home/virp_smmak/mportal/alerting/mportal-email-from-edit-v1
DST=/opt/maintenance-portal-demo
cd "$DST"

# Остановить периодические LIVE-отправки на время обновления.
sudo systemctl disable --now mportal-email-alert.timer
sudo systemctl stop mportal-email-alert.service || true

# Резервная копия SQLite с транзакционно согласованным снимком.
sudo install -d -o root -g root -m 700 /root/mportal-smtp-from-backup
sudo python3 - <<'PY'
import sqlite3
from datetime import datetime
path = '/root/mportal-smtp-from-backup/portal-' + datetime.now().strftime('%Y%m%d-%H%M%S') + '.sqlite3'
a = sqlite3.connect('file:/var/lib/maintenance-portal/audit_demo.sqlite3?mode=ro', uri=True)
b = sqlite3.connect(path)
a.backup(b)
assert b.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
a.close(); b.close()
print('BACKUP OK:', path)
PY

# Новые скрипты: не заменяем напрямую работающие файлы приложения.
sudo install -o root -g root -m 644 "$SRC/apply_editable_from_patch.py" "$DST/"
sudo install -o root -g root -m 644 "$SRC/test_editable_from.py" "$DST/"
sudo install -o root -g root -m 644 "$SRC/smtp_test_once.py" "$DST/"

.venv/bin/python apply_editable_from_patch.py --check
# Ожидается EDITABLE FROM PATCH CHECK: PASS (no files or database changed)

sudo .venv/bin/python apply_editable_from_patch.py --apply
.venv/bin/python -m py_compile alert_settings.py alert_admin.py mportal_mail_live.py

# Первый перезапуск автоматически добавляет колонку smtp_from.
sudo systemctl restart maintenance-portal
systemctl is-active maintenance-portal

# 6 новых регрессионных тестов. Если в каталоге есть прежний тестовый набор,
# добавьте test_mportal_mail_live к команде: итого будет 16 тестов.
.venv/bin/python -m unittest -v test_editable_from
```

При изменении исходных файлов автоматически создаются резервные копии:

- `alert_settings.py.before-editable-from`
- `alert_admin.py.before-editable-from`
- `templates/alerting.html.before-editable-from`
- `mportal_mail_live.py.before-editable-from`

Патч не применяется повторно и откажется работать, если ожидаемые строки в файлах отсутствуют.

## 3. Проверка и включение

Под Admin открыть `https://mportal.example.com/admin/alerting`. В разделе SMTP изменить **From (email address)**, сохранить. Проверить текущие значения без отправки:

```bash
cd /opt/maintenance-portal-demo
sudo .venv/bin/python - <<'PY'
import alert_settings
s = alert_settings.smtp_config('/var/lib/maintenance-portal/audit_demo.sqlite3')
print('SMTP:',s['host'],s['port'])
print('From:',s['from'])
print('Auth:',s['auth'],'STARTTLS:',s['starttls'])
PY

# Проверка будущего тестового письма, без SMTP:
sudo .venv/bin/python smtp_test_once.py --host-id 10917 --host-name ML2SRV01

# Только по явному решению: отправить ОДНО тестовое письмо на адрес,
# уже настроенный для ML2SRV01 через панель. Если получателей больше одного,
# необходимо указать --to с конкретным адресом из Admin Panel:
sudo .venv/bin/python smtp_test_once.py --host-id 10917 --host-name ML2SRV01 --send
```

Когда всё проверено, восстановите ранее действовавший автоматический таймер:

```bash
sudo systemctl enable --now mportal-email-alert.timer
systemctl list-timers mportal-email-alert.timer
sudo journalctl -u mportal-email-alert.service -n 50 --no-pager
```

**Внимание:** это реальный LIVE-таймер, а не DRY_RUN. `SMTP ACCEPTED` подтверждает лишь принятие письма Relay, не доставку в конечный ящик. Для неисправного Postfix нужна отдельная диагностика.

## Откат

При проблемах сначала выключить таймер:

```bash
sudo systemctl disable --now mportal-email-alert.timer
sudo systemctl stop mportal-email-alert.service || true
cd /opt/maintenance-portal-demo
sudo cp -a alert_settings.py.before-editable-from alert_settings.py
sudo cp -a alert_admin.py.before-editable-from alert_admin.py
sudo cp -a templates/alerting.html.before-editable-from templates/alerting.html
sudo cp -a mportal_mail_live.py.before-editable-from mportal_mail_live.py
sudo systemctl restart maintenance-portal
```

Новая `smtp_from` колонка остаётся в базе (старой версии она не мешает). Очередь и курсор сохраняются. Не включайте LIVE-таймер до устранения причины отката.
