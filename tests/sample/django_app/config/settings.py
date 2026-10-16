import six  # noqa: F401  (loaded when the application starts)

INSTALLED_APPS = ['django.contrib.admin', 'accounts', 'api']
MIDDLEWARE = ['django.middleware.security.SecurityMiddleware']
ROOT_URLCONF = 'config.urls'
WSGI_APPLICATION = 'config.wsgi.application'
