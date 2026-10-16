from jinja2 import Template


def render_page(data):
    return Template('{{ x }}').render(x=data)
