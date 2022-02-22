from django.db import models
from django.conf import settings

from rest.models import RestModel, MetaDataModel, MetaDataBase, RestValidationError, PermisionDeniedException
from rest import helpers as rest_helpers


TODO_STATES = [
    (0, "new"),
    (1, "in progress"),
    (2, "paused"),
    (-1, "archived"),
    (10, "completed"),
]


class TODO(models.Model, RestModel, MetaDataModel):
    """
    Simple TODO Example that will auto have a default graph for rest by inheriting RestModel.
    By inheriting MetaDataModel and creating a TODOMetaData model we can assign key/value pairs.

    """
    # this sub class allows us to define rest properties
    class RestMeta:
        # when using search what fields do we want to look into
        SEARCH_FIELDS = ["assigned_to__username", "assigned_to__email", "assigned_to__first_name", "assigned_to__last_name"]
        # default is your graph returned normally
        # list is your graph when returned in a list response
        GRAPHS = {
            "default": {
                "extra": [
                    "uuid",  # this will just call the uuid method below
                    "metadata",  # this exposes our key/value metadata
                    ("get_state_display", "state_display")  # this is how you rename a methods graph key, get_XXX_display is a django choices feature
                ],  # example of calling method on instance (method, key used in graph)
                "graphs": {
                    "assigned_to": "basic",
                    "group": "basic"
                }
            },
            "list": {
                "graphs": {
                    "self": "default"  # this tells the graph to be the same as the default
                }
            }
        }
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)

    subject = models.CharField(db_index=True, max_length=200)
    description = models.TextField(null=True, blank=True, default=None)
    kind = models.CharField(db_index=True, max_length=80, default="task")
    state = models.IntegerField(default=0, choices=TODO_STATES)

    group = models.ForeignKey("account.Group", default=None, null=True, blank=True, related_name="todos", on_delete=models.CASCADE)    
    assigned_to = models.ForeignKey("account.Member", default=None, null=True, blank=True, related_name="todos", on_delete=models.CASCADE)
    
    def uuid(self):
        return "wait this isn't a uiuid for {}".format(self.pk)


class TODOMetaData(MetaDataBase):
    parent = models.ForeignKey(TODO, related_name="properties", on_delete=models.CASCADE)

