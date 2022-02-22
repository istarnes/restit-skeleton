from .models import *

from rest.views import *
from rest.decorators import *
from rest import search
from rest import helpers


@url(r'^plog$')
@url(r'^plog/(?P<plog_id>\d+)$')
@staff_required
def plog_handler(request, plog_id=None):
    if not plog_id:
        min_pk = getattr(settings, "PLOG_STALE_ID", 0)
        return PersistentLog.on_rest_list(request, qset=PersistentLog.objects.filter(pk__gte=min_pk))
    return PersistentLog.on_rest_request(request, plog_id)

@urlGET (r'^plog_old$')
@staff_required
def plogList(request):
    PersistentLog.on_request_handle()

    graph = request.DATA.get("graph", "default")
    qset = PersistentLog.objects.all()
    if request.group:
        qset = qset.filter(group=request.group)

    ip = request.DATA.get("ip")
    if ip:
        qset = qset.filter(session__ip=ip)

    path = request.DATA.get("path")
    if path:
        qset = qset.filter(remote_path__icontains=path)
    
    method = request.DATA.get("method")
    if method:
        qset = qset.filter(method=method)

    action = request.DATA.get("action")
    if action:
        qset = qset.filter(action=action)
    
    component = request.DATA.get("component")
    if component:
        qset = qset.filter(component=component)
    
    pkey = request.DATA.get("pkey")
    if pkey:
        qset = qset.filter(pkey=pkey)

    username = request.DATA.get("username")
    if username:
        qset = qset.filter(user__username=username)
    
    term = request.DATA.get("term")
    if term:
        qset = qset.filter(message__icontains=term)
    
    return restList(request, qset.order_by('-when'), **PersistentLog.getGraph(graph))


@urlGET (r'^list$')
def auditList(request):
    """
    | Parameter: model=<string> (default=all)
    | Parameter: id=<int> (default=all)
    | Parameter: attributes=<string> (default=all)
    | Parameter: user=<id|username> (default=all)
    |
    | Return: audit log entries
    """
    ret = AuditLog.objects.all()
    
    model = request.DATA.get('model')
    if model:
        ret = ret.filter(model=model)

    id = request.DATA.get('id')
    if id:
        ret = ret.filter(pkey=int(id))

    attributes = request.DATA.get('attributes')
    if attributes:
        attributes = attributes.split(',')
        print(attributes)
        ret = ret.filter(attribute__in = attributes)

    user = request.DATA.get('user')
    if user:
        ret = ret.filter(user=user)

    return restList(request, ret, sort='-when',
        fields=(
            'when',
            'model',
            'pkey',
            'attribute',
            'user.id',
            'user.username',
            'reference',
            'how',
            'referer',
            'stack',
            'oldval',
            'newval',
        ), recurse_into=(
            'user',
        ), require_perms=(
            'auditlog.can_read',
        ),
    )


@url(r'^nuke$')
@staff_required
def nuke_log_data(request):
    # nuclear option used for testing system to clear out all wallet data
    # make sure this is enabled for this setup
    confirm_nuke = request.DATA.get("nuke_code", None)
    if confirm_nuke != "launch" or not getattr(settings, "CAN_NUKE_DATABASE", False):
        return restPermissionDenied(request)

    # first nuke all transactions
    PersistentLog.objects.all().delete()
    AuditLog.objects.all().delete()
    SessionLog.objects.all().delete()
    return restStatus(request, True)

