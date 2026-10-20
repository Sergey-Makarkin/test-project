"""Admin-only project configuration routes. No changes to Zabbix or AD."""
from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, HTMLResponse

import project_access as access


def install_admin_routes(app, db_path, templates, identity, check_csrf, allowed_hosts):
    router = APIRouter(prefix='/admin')

    def admin_user(request):
        user = identity(request)
        if not access.enabled():
            raise HTTPException(404, 'Project access management is disabled')
        if user['scope'] != 'admin' or user['role'] != 'admin':
            raise HTTPException(403, 'Administrator role required')
        return user

    def authorize_post(request, csrf_token):
        check_csrf(request, csrf_token)
        return admin_user(request)

    def go():
        return RedirectResponse('/admin', status_code=303)

    @router.get('', response_class=HTMLResponse)
    def home(request: Request):
        user = admin_user(request)
        snapshot = access.admin_snapshot(db_path, allowed_hosts())
        return templates.TemplateResponse(request, 'admin.html', {
            'user': user, 'csrf': user['csrf'], **snapshot,
        })

    @router.get('/directory/group', response_class=HTMLResponse)
    def check_group(request: Request, name: str = ''):
        admin_user(request)
        group = access.find_ad_group(name)
        # Small plain HTML page; template automatically escapes user input.
        return templates.TemplateResponse(request, 'admin_group.html', {
            'group': group,
        })

    @router.post('/projects/create')
    def create_project(request: Request, name: str = Form(...), csrf_token: str = Form(...)):
        user = authorize_post(request, csrf_token)
        access.create_project(db_path, user['name'], name)
        return go()

    @router.post('/projects/{project_id}/groups/add')
    def add_group(request: Request, project_id: int, group_name: str = Form(...),
                  csrf_token: str = Form(...)):
        user = authorize_post(request, csrf_token)
        group = access.find_ad_group(group_name)
        access.add_group(db_path, user['name'], project_id, group)
        return go()

    @router.post('/projects/{project_id}/groups/{group_id}/remove')
    def remove_group(request: Request, project_id: int, group_id: int,
                     csrf_token: str = Form(...), confirmation: str = Form('')):
        user = authorize_post(request, csrf_token)
        if confirmation != 'remove':
            raise HTTPException(422, 'Explicit removal confirmation required')
        access.remove_group(db_path, user['name'], project_id, group_id)
        return go()

    @router.post('/projects/{project_id}/hosts/add')
    def add_host(request: Request, project_id: int, host_id: str = Form(...),
                 csrf_token: str = Form(...)):
        user = authorize_post(request, csrf_token)
        if host_id not in allowed_hosts():
            raise HTTPException(403, 'Host is not an enabled Windows host')
        access.assign_host(db_path, user['name'], project_id, host_id)
        return go()

    @router.post('/projects/{project_id}/hosts/{host_id}/release')
    def release_host(request: Request, project_id: int, host_id: str,
                     confirmation: str = Form(''), csrf_token: str = Form(...)):
        user = authorize_post(request, csrf_token)
        if confirmation != 'release':
            raise HTTPException(422, 'Explicit release confirmation required')
        access.release_host(db_path, user['name'], project_id, host_id)
        return go()

    @router.post('/hosts/{host_id}/move')
    def move_host(request: Request, host_id: str, target_project_id: int = Form(...),
                  confirmation: str = Form(''), csrf_token: str = Form(...)):
        user = authorize_post(request, csrf_token)
        if confirmation != 'move':
            raise HTTPException(422, 'Explicit transfer confirmation required')
        if host_id not in allowed_hosts():
            raise HTTPException(403, 'Host is not an enabled Windows host')
        access.move_host(db_path, user['name'], host_id, target_project_id)
        return go()

    @router.post('/projects/{project_id}/delete')
    def delete_project(request: Request, project_id: int,
                       confirmation: str = Form(''), csrf_token: str = Form(...)):
        user = authorize_post(request, csrf_token)
        if confirmation != 'delete-empty':
            raise HTTPException(422, 'Explicit deletion confirmation required')
        access.delete_empty_project(db_path, user['name'], project_id)
        return go()

    app.include_router(router)
