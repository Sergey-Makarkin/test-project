# Email Alerting Settings · Этап 2 (CONFIG ONLY / DRY RUN)

**Привязано к действующей версии Maintenance Portal после Project RBAC** (`project_admin.install_admin_routes`, `project_access.ensure_schema`).

## Что добавляется

- `/admin/alerting`, доступная только администратору с действующими правами AD.
- Получатели для GENERAL и отдельных проектов; проект без адресов **не использует** общий email.
- Списки критичных служб и исключения: Global → Project → Host; режим Critical или Exclude.
- Только точные короткие Windows Service Names; High (4) / Disaster (5).
- Read-only предпросмотр итоговой маршрутизации и регулярного выражения LLD по каждому хосту.
- Новые таблицы `mp_alert_*` внутри имеющейся SQLite и аудит администрирования.

**НЕТ** отправки SMTP, изменения Zabbix API, перенастройки LLD, запуска systemd timer, новой авторизации или изменения существующего агрегатора. Ввод адресов и правил на этом этапе изменяет только новые таблицы конфигурации портала.

## Копирование из Git

Положить эти 6 файлов в `/home/virp_smmak/mportal/alerting/admin-stage2/`:

- `alert_settings.py`
- `alert_admin.py`
- `alerting.html`
- `apply_alert_admin_patch.py`
- `test_alert_settings.py`
- `test_alert_admin.py`

На `ml2zbx01`:

```bash
SRC=/home/virp_smmak/mportal/alerting/admin-stage2
DST=/opt/maintenance-portal-demo

sudo install -o root -g root -m 644 "$SRC/alert_settings.py" "$DST/alert_settings.py"
sudo install -o root -g root -m 644 "$SRC/alert_admin.py" "$DST/alert_admin.py"
sudo install -o root -g root -m 644 "$SRC/alerting.html" "$DST/templates/alerting.html"
sudo install -o root -g root -m 644 "$SRC/apply_alert_admin_patch.py" "$DST/apply_alert_admin_patch.py"
sudo install -o root -g root -m 644 "$SRC/test_alert_settings.py" "$DST/test_alert_settings.py"
sudo install -o root -g root -m 644 "$SRC/test_alert_admin.py" "$DST/test_alert_admin.py"

cd "$DST"
.venv/bin/python -m py_compile alert_settings.py alert_admin.py apply_alert_admin_patch.py
.venv/bin/python -m unittest -v test_alert_settings test_alert_admin
.venv/bin/python apply_alert_admin_patch.py --check
```

**Ожидаем** `Ran 18 tests ... OK` и `ALERT ADMIN PATCH CHECK: PASS (no files or database changed)`.

## Защищённый backup перед применением

```bash
sudo install -d -o root -g root -m 700 /root/mportal-alerting-backup
sudo python3 - <<'PY'
import sqlite3
src = sqlite3.connect('file:/var/lib/maintenance-portal/audit_demo.sqlite3?mode=ro', uri=True)
dst = sqlite3.connect('/root/mportal-alerting-backup/audit-pre-alert-admin.sqlite3')
with dst:
    src.backup(dst)
print('Consistent SQLite backup OK')
src.close(); dst.close()
PY
```

Кодовый патч автоматически создаёт отдельные резервные копии `app.py.before-alert-admin`, `admin.html.before-alert-admin`. Не удаляйте старые `.before-project-rbac`.

## Применение (только после успешного `--check`)

```bash
cd /opt/maintenance-portal-demo
sudo .venv/bin/python apply_alert_admin_patch.py --apply
sudo systemctl restart maintenance-portal
systemctl is-active maintenance-portal
sudo journalctl -u maintenance-portal -n 35 --no-pager
```

Откройте под Admin: `https://mportal.example.com/admin` → **Email Alerting** → `/admin/alerting`.

Проверить безопасно:

1. Пустые адреса изначально; без SMTP писем не будет.
2. Добавьте только согласованные реальные получатели GENERAL и Project Alfa.
3. Добавьте глобальное правило `WinRM` (High) и для тестового хоста исключение `WinRM`, проверьте preview.
4. Убедитесь, что проектные получатели не показываются для GENERAL, и наоборот.
5. Войдите под General/Project Operator: `/admin/alerting` должен возвращать 403.
6. Подтвердите, что действующее создание и остановка Maintenance по-прежнему работают, но не создавайте новые Maintenance без надобности.

Обратите внимание: новые правила **пока не синхронизируются** с Zabbix LLD. Тестовый `w32time` на ML2SRV01 остаётся под существующим ручным пилотным макросом.

## Откат интерфейса без отключения Project RBAC

```bash
sudo cp -a /opt/maintenance-portal-demo/app.py.before-alert-admin \
  /opt/maintenance-portal-demo/app.py
sudo cp -a /opt/maintenance-portal-demo/templates/admin.html.before-alert-admin \
  /opt/maintenance-portal-demo/templates/admin.html
sudo systemctl restart maintenance-portal
```

Новые таблицы `mp_alert_*` можно оставить: прежний портал их не использует. Не отключайте `PORTAL_PROJECT_RBAC=1` и не откатывайте `project_access`.
