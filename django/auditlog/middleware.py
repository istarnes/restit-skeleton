from django.conf import settings

class LogRequest(object):
    last_request = None
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.process_request(request)

    def process_request(self, request):
        # LogRequest.last_request = request
        if request.path.startswith("/rpc/"):
            if hasattr(settings, "DEBUG_REST_END_POINTS") and settings.DEBUG_REST_END_POINTS:
                for ep in settings.DEBUG_REST_END_POINTS:
                    if request.path.startswith(ep):
                        request.DATA.log()
                        break
            elif hasattr(settings, "DEBUG_REST_INPUT") and settings.DEBUG_REST_INPUT:
                request.DATA.log()
        response = self.get_response(request)
        return response
