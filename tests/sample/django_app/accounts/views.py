import yaml
from django.http import HttpResponse
from django.views import View

from utils.helpers import render_page


def login_view(request):
    settings = yaml.load(request.body, Loader=yaml.Loader)  # the kind of thing an advisory is about
    return HttpResponse(render_page(settings))


class ProfileView(View):
    def get(self, request):
        return HttpResponse('profile')
