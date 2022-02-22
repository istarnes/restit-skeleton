from django.db import models
from account.models import User
from django.db.models.base import ModelBase
from django.template.loader import render_to_string
from django.template import RequestContext

try:
    from django.template.base import TemplateDoesNotExist
except ImportError: # Removed in Django 1.9
    from django.template import TemplateDoesNotExist

from django.apps import apps

from django.conf import settings

from sessionlog.models import SessionLog
# from comment.models import Comment

import inspect
import os

class StatBase(models.Model):
    # _aliases specifies lookup table for each component/action set.
    # 	'COMPONENT.ACTION': {
    # 		'ALIAS_TO': ('ALIAS_FROM', TYPE),
    # 		...
    # 	},
    #
    # you can now access stat object using the specified aliases
    # Initialize: obj = Stat(component="video", action="post", video=123)
    # Initialize: obj = Stat(component="video", action="post", video=Video.object.get(pk=123))
    # Read: obj.video (returns Video object)
    # Set: obj.video = 123
    # Set: obj.video = Video.object.get(123)

    class Meta:
        abstract = True
        ordering = ["-created", "-id"]

    _render_base = 'statistic'
    _fixed = False
    _aliases = {}
    _call_args = {}

    created = models.DateTimeField(auto_now_add=True, editable=False, help_text="When stat was logged")
    component = models.SlugField(max_length=32, null=True, blank=True, db_index=True)
    action = models.SlugField(max_length=32, db_index=True)
    subtype = models.SlugField(max_length=32, null=True, blank=True, db_index=True)
    user = models.ForeignKey(User, null=True, on_delete=models.CASCADE)
    related_user = models.ForeignKey(User, null=True, blank=True, related_name='+', on_delete=models.CASCADE)
    session = models.ForeignKey(SessionLog, null=True, blank=True, on_delete=models.CASCADE)
    public = models.BooleanField(default=False, db_index=True, help_text="Show item to all")

    int1 = models.IntegerField(null=True, blank=True, db_index=True)
    str1 = models.TextField(null=True, blank=True)
    int2 = models.IntegerField(null=True, blank=True, db_index=True)
    str2 = models.TextField(null=True, blank=True)
    int3 = models.IntegerField(null=True, blank=True, db_index=True)
    str3 = models.TextField(null=True, blank=True)

    @classmethod
    def fixStatic(cls):
        for name in cls._aliases:
            add = {}
            for alias in cls._aliases[name]:
                if isinstance(cls._aliases[name][alias][1], str):
                    if isinstance(cls._aliases[name][alias], tuple):
                        cls._aliases[name][alias] = list(cls._aliases[name][alias])
                    elif isinstance(cls._aliases[name][alias], list):
                        pass
                    else:
                        continue
                    appname, modelname = cls._aliases[name][alias][1].split('.')
                    model = apps.get_model(appname, modelname)
                    if not model:
                        raise Exception("bad model: %s.%s" % (appname, modelname))
                    cls._aliases[name][alias][1] = model
                    if not ((alias+"_id") in cls._aliases[name] or alias[-3:] == "id"):
                        add[alias+"_id"] = (cls._aliases[name][alias][0], int)
            if add:
                cls._aliases[name].update(add)
        cls._fixed = True

    @classmethod
    def log(cls, request=None, **kwargs):
        if request:
            if not 'session' in kwargs:
                kwargs['session'] = SessionLog.GetSession(request)
            if request.user and request.user.is_authenticated and not 'user' in kwargs:
                kwargs['user'] = request.user
        obj = cls(**kwargs)
        obj.save()
        return obj

    def serialize(self, request=None):
        data = {}
        try:
            data['user'] = self.user.member.serialize(request)
        except (AttributeError, User.DoesNotExist):
            data['user'] = None
        try:
            data['related_user'] = self.related_user.member.serialize(request)
        except (AttributeError, User.DoesNotExist):
            data['related_user'] = None

        for f in self._meta.fields:
            if f.name[:3] in ('str', 'int') or \
               f.name[:1] == '_' or \
               f.name in ('session',) or \
               f.name in data:
                continue
            data[f.name] = getattr(self, f.name)
            if hasattr(data[f.name], 'serialize'):
                data[f.name] = data[f.name].serialize(request)


        comp = "%s.%s" % (self.component, self.action)
        if comp in self._aliases:
            aliases = self._aliases[comp]
            for name in aliases.keys():
                if name[:1] == '_':
                    continue
                if name[-3:] == "_id" and name[:-3] in aliases:
                    continue
                try:
                    data[name] = getattr(self, name)
                    if hasattr(data[name], 'serialize'):
                        data[name] = data[name].serialize(request)
                except:
                    pass
        return data;

    def render(self, request=None, suffix='.html'):
        # TODO: check cache

        opts = {
            "nocache": False,
        }

        self._call_args = self._call_args.copy()
        self._call_args['request'] = request

        subtyped_action = self.action
        if self.subtype:
            subtyped_action = self.action + '_' + self.subtype

        for tmpl in (
            (self._render_base, 'render', self.component or '', subtyped_action or 'noaction'),
            (self._render_base, 'render', self.component or '', self.action or 'noaction'),
            (self._render_base, 'render', self.action or 'noaction'),
            (self._render_base, 'render', self.component or '', 'generic'),
            (self._render_base, 'render', 'generic'),
        ):
            try:
                ret = render_to_string(os.path.join(*tmpl) + suffix, {"stat": self})
                # parse options
                while ret.startswith("#OPTION:"):
                    spl = ret.split("\n", 1)
                    opt = spl[0].split(":", 1)[1].strip()
                    if "=" in opt:
                        (name, value) = opt.split("=", 1)
                    else:
                        (name, value) = (opt, True)
                    opts[name] = value
                    ret = spl[1]
                # TODO: add to cache
                return ret
            except TemplateDoesNotExist:
                pass
        return None

    def _comments_token(self, related, idname):
        return Comment.make_token(related, getattr(self, idname))

    def _comments_count(self, related, idname):
        return Comment.count(related, getattr(self, idname))

    def __unicode__(self):
        return (
            ((self.component + '.') if self.component else '') +
            self.action +
            (('.' + self.subtype) if self.subtype else '') +
            (':' + self.user.username if self.user else '')
        )

    def __init__(self, *args, **kwargs):
        if not self._fixed:
            self.fixStatic()

        comp = kwargs.get('component', '') + '.' + kwargs.get('action', '')
        aliases = []
        for name in self._aliases.get(comp, {}):
            try:
                aliases.append((name, kwargs.pop(name),))
            except KeyError:
                pass
        super(StatBase, self).__init__(*args, **kwargs)
        for alias in aliases:
            setattr(self, alias[0], alias[1])

    def __setattr__(self, name, value):
        try:
            comp = (self.component or "") + "." + (self.action or "")
            alias = self._aliases.get(comp, {}).get(name, None)
            if not alias:
                return super(StatBase, self).__setattr__(name, value)
            if isinstance(alias[1], ModelBase):
                if value is None:
                    return super(StatBase, self).__setattr__(alias[0], None)
                elif isinstance(type(value), ModelBase):
                    return super(StatBase, self).__setattr__(alias[0], value.pk)
                else:
                    obj = alias[1].objects.get(pk=value)
                    return super(StatBase, self).__setattr__(alias[0], obj.pk)
            return super(StatBase, self).__setattr__(alias[0], value)
        except AttributeError:
            pass
        return super(StatBase, self).__setattr__(name, value)

    def __getattr__(self, name):
        try:
            return super(StatBase, self).__getattribute__(name)
        except AttributeError:
            if name in ("component", "action", "_aliases"):
                raise
            comp = (self.component or "") + "." + (self.action or "")
            alias = self._aliases.get(comp, {}).get(name, None)
            if not alias:
                raise

            if type(alias) in (str,unicode):
                storedvalue = self
                for x in alias.split('.'):
                    storedvalue = getattr(storedvalue, x)
                return storedvalue
            elif type(alias[0]) in (tuple, list):
                func = getattr(self, alias[0][0])

                args = list(alias[0])
                args.pop(0)

                kwargs = {}
                take = inspect.getargspec(func)[0]
                for arg in self._call_args:
                    if arg in take:
                        kwargs[arg] = self._call_args[arg]

                storedvalue = func(*args, **kwargs)
            else:
                storedvalue = super(StatBase, self).__getattribute__(alias[0])
            if storedvalue == None:
                return None

            if isinstance(alias[1], ModelBase):
                # stored type references another object
                ret = alias[1].objects.get(pk=storedvalue)
                if hasattr(ret, '_request') and ret._request == None:
                    ret._request = self._call_args.get('request')
                return ret

            if isinstance(storedvalue, alias[1]):
                # stored type is already of the correct type
                return storedvalue

            # try to coerce the type
            return alias[1](storedvalue)

class Stat(StatBase):
    """
    Generic Statistics
    """

    _aliases = settings.STAT_ALIASES

