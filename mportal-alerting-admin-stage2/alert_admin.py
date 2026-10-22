"""Admin-only email alert policy UI. Does not send mail or modify Zabbix."""
from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

import alert_settings as settings
import project_access


def install_alert_admin_routes(app, db_path, templates, identity, check_csrf, allowed_hosts):
    router = APIRouter(prefix='/admin/alerting')

    def admin(request):
        user = identity(request)
        if not project_access.enabled():
            raise HTTPException(404, 'Project access management is disabled')
        if user.get('scope') != 'admin' or user.get('role') != 'admin':
            raise HTTPException(403, 'Administrator role required')
        return user

    def authorize_post(request, token):
        check_csrf(request, token)
        return admin(request)

    def go():
        return RedirectResponse('/admin/alerting', status_code=303)

    def safe_change(callback, *args, **kwargs):
        try:
            return callback(*args, **kwargs)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @router.get('', response_class=HTMLResponse)
    def home(request: Request, host_id: str = ''):
        user = admin(request)
        data = settings.snapshot(db_path)
        all_hosts = allowed_hosts()
        hosts = [{'hostid': str(k), 'name': v.get('name') or v.get('host') or str(k)}
                 for k, v in all_hosts.items()]
        hosts.sort(key=lambda h: h['name'].lower())
        preview = None
        if host_id:
            if host_id not in all_hosts:
                raise HTTPException(404, 'Windows host not in portal scope')
            preview = settings.effective_for_host(db_path, host_id)
            preview['regex'] = settings.build_lld_regex(preview['critical_services'])
            preview['host_name'] = all_hosts[host_id].get('name') or all_hosts[host_id].get('host')
        return templates.TemplateResponse(request, 'alerting.html', {
            'user': user, 'csrf': user['csrf'], 'hosts': hosts, 'preview': preview, **data,
        })

    @router.post('/recipients/general')
    def general_recipients(request: Request, recipients: str = Form(''), csrf_token: str = Form(...)):
        user = authorize_post(request, csrf_token)
        safe_change(settings.set_general_recipients, db_path, user['name'], recipients)
        return go()

    @router.post('/recipients/project/{project_id}')
    def project_recipients(request: Request, project_id: int, recipients: str = Form(''),
                           csrf_token: str = Form(...)):
        user = authorize_post(request, csrf_token)
        safe_change(settings.set_project_recipients, db_path, user['name'], project_id, recipients)
        return go()

    @router.post('/rules')
    def rule(request: Request, scope: str = Form(...), service_name: str = Form(...),
             mode: str = Form(...), severity: int = Form(4),
             project_id: str = Form(''), host_id: str = Form(''),
             csrf_token: str = Form(...)):
        user = authorize_post(request, csrf_token)
        safe_change(settings.add_or_update_rule, db_path, user['name'],
                    scope=scope, project_id=project_id or None, host_id=host_id or None,
                    service_name=service_name, mode=mode, severity=severity,
                    allowed_hostids=set(allowed_hosts()))
        return go()

    @router.post('/rules/{rule_id}/delete')
    def delete_rule(request: Request, rule_id: int, csrf_token: str = Form(...)):
        user = authorize_post(request, csrf_token)
        safe_change(settings.remove_rule, db_path, user['name'], rule_id)
        return go()

    app.include_router(router)
