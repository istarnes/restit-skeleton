from django.template.loader import render_to_string		
try:
    from django.template.base import TemplateDoesNotExist
except ImportError: # Removed in Django 1.9
    from django.template import TemplateDoesNotExist
from django.template import RequestContext
from django.core.mail import EmailMultiAlternatives
from django.conf import settings
import logging

__all__ = ['render_to_mail']

def render_to_mail(name, context):
    if not isinstance(context, RequestContext):
        tmp = RequestContext(context.get('request', None))
        tmp.update(context)
        context = tmp
    context['newline'] = "\n"

    if 'to' in context:
        toaddrs = context['to']
    else:
        try:
            toaddrs = render_to_string(name + ".to", context).splitlines()
        except TemplateDoesNotExist:
            return
    if type(toaddrs) in (str, str):
        toaddrs = [ toaddrs ]
    try:
        while True:
            toaddrs.remove('')
    except ValueError:
        pass
    if len(toaddrs) == 0:
        logging.getLogger("exception").error("Sending email to no one: %s" % name)
        return

    try:
        html_content = render_to_string(name + ".html", context)
    except TemplateDoesNotExist:
        html_content = None
        pass
    
    try:
        text_content = render_to_string(name + ".txt", context)
    except TemplateDoesNotExist:
        if html_content == None:
            raise
        text_content = ""
        pass

    if 'from' in context:
        fromaddr = context['from']
    else:
        try:
            fromaddr = render_to_string(name + ".from", context).rstrip()
        except TemplateDoesNotExist:
            logging.getLogger("exception").error("Sending email without from address: %s" % name)
            return

    if 'subject' in context:
        subject = context['subject']
    else:
        try:
            subject = render_to_string(name + ".subject", context).rstrip()
        except TemplateDoesNotExist:
            logging.getLogger("exception").error("Sending email without subject: %s" % name)
            return

    email = EmailMultiAlternatives(subject, text_content, fromaddr, toaddrs)
    if html_content:
        email.attach_alternative(html_content, "text/html")

    try:
        email.send()
    except Exception as e:
        logging.getLogger("exception").error("Error sending email: %s: %s" % (type(e).__name__, str(e)))
        pass
