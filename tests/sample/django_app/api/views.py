import requests
from django.http import JsonResponse


def reports(request):
    return JsonResponse(requests.get('https://example.test/r').json())


def status(request):
    return JsonResponse({'ok': True})
