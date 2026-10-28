# MPortal Email Alerting LIVE: установка на ml2zbx01

## Состав

* `apply_smtp_live_patch.py` — ограниченный патч существующей панели Administration → Email Alerting; `--check` только проверяет.
* `mportal_mail_live.py` — рабочий обработчик событий и реальная SMTP-отправка через внутренний Relay.
* `test_mportal_mail_live.py` — тесты с подменным SMTP без отправки писем.
* `mportal-email-alert.service` и `.timer` — обработчик раз в минуту под `maintenance-portal`.
* Существующие `zabbix_mail_policy_dryrun.py`, `alert_settings.py`, `alert_admin.py`, `templates/alerting.html` сохраняются; они необходимы для интеграции. Режим старого DRY_RUN остаётся независимым.

## Возможности и важные ограничения

* Живая отправка, только SMTP host/port из Admin Panel; без AUTH, без TLS. From **жёстко** `mportal@example.com`.
* Реальные письма по новым после baseline событиям Zabbix High/Disaster; активная служба должна входить в список Critical Services. Недоступность Zabbix Agent также требует фактического уровня триггера High/Disaster.
* 120 секунд на объединение проблем одного сервера, сообщения UPDATE и RECOVERED, напоминание через 4 часа, учёт Maintenance.
* Сервера проектов никогда не используют общий список получателей.
* Курсор Zabbix и очередь хранятся **в новой** `/var/lib/mportal-live/alerts.sqlite3`, не затрагивая старую DRY_RUN SQLite.
* Отправка повторяется при SMTP ошибке с интервалами 1, 2, 4, 8... до 60 минут. Подтверждённые для одного сообщения получатели не отправляются повторно, даже если другой получатель отклонён.
* SMTP `250` означает принятие Relay, **не** доставку в конечный ящик. Если Relay теряет принятые письма, наша очередь этого не увидит. Нужен ремонт / замена Relay и Postfix-трекинг.
* При обрыве процесса между приёмом SMTP и записью подтверждения в SQLite возможна повторная отправка. Гарантия at-least-once, не exactly-once.
* Мы не добавляем Zabbix Actions, не повышаем триггеры автоматически и не создаём новые события.

## 1. Перенос файлов

Распаковать через Git каталог `mportal-email-live-v1` на сервер, например `/home/virp_smmak/mportal/alerting/mportal-email-live-v1/`.

```bash
SRC=/home/virp_smmak/mportal/alerting/mportal-email-live-v1
DST=/opt/maintenance-portal-demo

# Проверяем наличие файлов перед установкой
ls -l "$SRC"/{apply_smtp_live_patch.py,mportal_mail_live.py,test_mportal_mail_live.py,mportal-email-alert.service,mportal-email-alert.timer}
test -f /home/virp_smmak/mportal/alerting/zabbix_mail_policy_dryrun.py

# Сохраняем копию существующей SQLite через Online Backup API
sudo install -d -o root -g root -m 700 /root/mportal-email-backup
sudo python3 - <<'PY'
import sqlite3
from pathlib import Path
from datetime import datetime
src=sqlite3.connect('file:/var/lib/maintenance-portal/audit_demo.sqlite3?mode=ro',uri=True)
dstpath=Path('/root/mportal-email-backup') / ('portal-' + datetime.now().strftime('%Y%m%d-%H%M%S') + '.sqlite3')
dst=sqlite3.connect(dstpath)
src.backup(dst)
assert dst.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
print('BACKUP OK:',dstpath)
dst.close();src.close()
PY

sudo install -o root -g root -m 644 "$SRC/apply_smtp_live_patch.py" "$DST/"
sudo install -o root -g root -m 644 "$SRC/mportal_mail_live.py" "$DST/"
sudo install -o root -g root -m 644 "$SRC/test_mportal_mail_live.py" "$DST/"
sudo install -o root -g root -m 644 /home/virp_smmak/mportal/alerting/zabbix_mail_policy_dryrun.py "$DST/"

cd "$DST"
.venv/bin/python -m py_compile mportal_mail_live.py apply_smtp_live_patch.py
.venv/bin/python apply_smtp_live_patch.py --check
```

## 2. Патч веб-админки и тесты

```bash
cd /opt/maintenance-portal-demo
sudo .venv/bin/python apply_smtp_live_patch.py --apply
.venv/bin/python -m py_compile alert_admin.py alert_settings.py mportal_mail_live.py
.venv/bin/python -m unittest -v test_mportal_mail_live
sudo systemctl restart maintenance-portal
systemctl is-active maintenance-portal
sudo journalctl -u maintenance-portal -n 30 --no-pager
```

В `/admin/alerting` теперь есть SMTP host и SMTP port. From фиксирован `mportal@example.com`.
Администратор вводит **действующий** Relay и порт, сохраняет. Отправка почты при сохранении конфигурации не происходит.

## 3. LIVE systemd

**Важное предварительное условие:** проверьте существующую DRY_RUN версию, выключите её таймер (если он ранее создавался вручную), чтобы одновременно не запустить два обработчика:

```bash
systemctl list-timers --all | grep -Ei 'mportal|alert' || true
```

Новый сервис не использует Zabbix Trigger Actions и не изменяет статус Maintenance Portal.

```bash
SRC=/home/virp_smmak/mportal/alerting/mportal-email-live-v1
sudo install -o root -g root -m 644 "$SRC/mportal-email-alert.service" /etc/systemd/system/
sudo install -o root -g root -m 644 "$SRC/mportal-email-alert.timer" /etc/systemd/system/
sudo systemctl daemon-reload

# До запуска проверьте настройки SMTP, получателей и критичных служб в /admin/alerting.
sudo systemctl start mportal-email-alert.service
sudo journalctl -u mportal-email-alert.service -n 50 --no-pager
```

На **первом запуске** ожидается `LIVE_BASELINE_CREATED ...; no historical messages queued or sent`. Старые проблемы не рассылаются.

**Включение автоматической реальной рассылки:**

```bash
sudo systemctl enable --now mportal-email-alert.timer
systemctl list-timers mportal-email-alert.timer
```

В следующие запуски обработчик начинает посылать настоящие письма по **новым** High/Disaster событиям после 120 секунд накопления.

## 4. Контроль

```bash
sudo journalctl -u mportal-email-alert.service -n 100 --no-pager
sudo /opt/maintenance-portal-demo/.venv/bin/python - <<'PY'
import sqlite3
p='/var/lib/mportal-live/alerts.sqlite3'
db=sqlite3.connect(f'file:{p}?mode=ro',uri=True)
for row in db.execute('SELECT status,count(*) FROM outbox GROUP BY status'):
    print(*row)
for row in db.execute("SELECT id,hostid,status,attempts,next_attempt,last_error FROM outbox WHERE status IN ('queued','retry') ORDER BY id DESC LIMIT 10"):
    print(row)
PY
```

`SMTP_ACCEPTED` означает, что Relay принял письмо. Проверьте фактическую доставку по Postfix Queue ID и журналам следующего сервера.

## 5. Аварийная остановка / откат

**Мгновенно остановить новые отправки:**

```bash
sudo systemctl disable --now mportal-email-alert.timer
sudo systemctl stop mportal-email-alert.service
```

**Вернуть исходную веб-админку**, если требуется:

```bash
cd /opt/maintenance-portal-demo
sudo cp -a alert_settings.py.before-smtp-live alert_settings.py
sudo cp -a alert_admin.py.before-smtp-live alert_admin.py
sudo cp -a templates/alerting.html.before-smtp-live templates/alerting.html
sudo systemctl restart maintenance-portal
```

Не удаляйте `/var/lib/mportal-live/alerts.sqlite3`: она содержит курсор, статус инцидентов и очередь. Не удаляйте также таблицу `mp_alert_smtp` во время отката: она не мешает старой версии и хранит настройки.

## 6. Права и секреты

Рабочий процесс запускается от системного пользователя `maintenance-portal`; `systemd` читает защищённый EnvironmentFile и передаёт параметры Zabbix в окружение процесса. База настроек портала открывается только на чтение, `/var/lib/mportal-live` принадлежит служебному пользователю. Не выводите `EnvironmentFile` в открытые логи.

Если база `/var/lib/maintenance-portal/audit_demo.sqlite3` недоступна `maintenance-portal`, проверьте разрешения и группу (не ослабляйте их до 777).
