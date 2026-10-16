"""Phase 7: the exposure graph. Import-level, Django-only, read-only.

Mini projects are written to tmp_path, one feature at a time. The tiny sample app in tests/sample/django_app is the
end-to-end case, with the expected result written down below.
"""
import hashlib
import json
from pathlib import Path

import pytest

from depscan.graph import LIMITATION, analyze_project
from depscan.graph.analysis import IMPORT_ALIASES, ImportMapper
from depscan.graph.django import expand_routes
from depscan.graph.modules import Target, discover, resolve
from depscan.models import Dependency, Match
from depscan.parsers import parse_file
from depscan.pipeline import DataBundle, scan_files
from depscan.scoring.config import load_config
from depscan.scoring.risk import compute_risk

SAMPLE = Path(__file__).parent / "sample"
APP = SAMPLE / "django_app"
CFG = load_config()


def project(tmp_path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return tmp_path


def dep(name, direct=True, requires=None, scope="runtime"):
    return Dependency(name=name, ecosystem="PyPI", spec="==1.0", version="1.0", lower_bound="1.0", direct=direct, scope=scope, requires=requires)


def analyze(tmp_path, files, *deps):
    return analyze_project(project(tmp_path, files), list(deps))


# a settings + urls skeleton most tests build on
BASE = {
    "config/__init__.py": "",
    "config/settings.py": "ROOT_URLCONF = 'config.urls'\nINSTALLED_APPS = ['app']\n",
    "app/__init__.py": "",
}


def level(a, name):
    e = a.exposure(name)
    return e["level"] if e else None


# ---------------------------------------------------------------- reading imports
def test_imports_plain_from_alias_relative_and_dynamic(tmp_path):
    idx = discover(project(tmp_path, {
        "pkg/__init__.py": "",
        "pkg/sub/__init__.py": "",
        "pkg/a.py": "import os\nimport yaml\nimport requests as rq\nfrom flask import Flask\nfrom . import b\nfrom .sub import c\nfrom ..up import x\n"
                    "import importlib\nm = importlib.import_module('jinja2.ext')\n__import__('six')\n",
        "pkg/b.py": "", "pkg/sub/c.py": "",
    }))
    refs = {c for r in idx.modules["pkg.a"].imports for c in r.candidates}
    assert {"os", "yaml", "requests", "flask.Flask", "flask", "pkg.b", "pkg.sub.c", "jinja2.ext", "six"} <= refs
    assert any(r.kind == "dynamic" for r in idx.modules["pkg.a"].imports)
    t = idx.modules["pkg.a"].table
    assert t["rq"] == ("requests", None) and t["b"] == ("pkg", "b") and t["Flask"] == ("flask", "Flask")


def test_relative_import_levels(tmp_path):
    idx = discover(project(tmp_path, {"p/__init__.py": "", "p/q/__init__.py": "", "p/q/m.py": "from . import s\nfrom .. import t\nfrom ..t import u\n",
                                      "p/q/s.py": "", "p/t.py": "", "p/u.py": ""}))
    cands = [r.candidates for r in idx.modules["p.q.m"].imports]
    assert ["p.q.s", "p.q"] in cands and ["p.t", "p"] in cands and ["p.t.u", "p.t"] in cands


def test_type_checking_imports_are_not_runtime_imports(tmp_path):
    idx = discover(project(tmp_path, {"m.py": "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import yaml\nelse:\n    import requests\nimport flask\n"}))
    by = {r.candidates[0]: r.typing_only for r in idx.modules["m"].imports}
    assert by["yaml"] is True and by["requests"] is False and by["flask"] is False


def test_unparsable_files_are_skipped_and_reported(tmp_path):
    a = analyze(tmp_path, {**BASE, "app/broken.py": "def (:\n", "app/ok.py": "import yaml\n"}, dep("pyyaml"))
    assert a.index.unparsable == ["app/broken.py"]
    assert any("1 Python file(s) could not be parsed" in w and "app/broken.py" in w for w in a.warnings)


def test_virtualenvs_and_node_modules_are_not_read(tmp_path):
    idx = discover(project(tmp_path, {"app.py": "import yaml\n", ".venv/lib/x.py": "import evil\n", "node_modules/y.py": "import evil\n",
                                      "site-packages/z.py": "import evil\n", "pkg.egg-info/w.py": "import evil\n"}))
    assert set(idx.modules) == {"app"}


def test_src_layout_modules_are_named_from_the_src_folder(tmp_path):
    idx = discover(project(tmp_path, {"src/mypkg/__init__.py": "", "src/mypkg/core.py": "import yaml\n"}))
    assert "mypkg.core" in idx.modules and "src.mypkg.core" not in idx.modules


def test_resolve_prefers_project_modules_then_external_then_stdlib(tmp_path):
    idx = discover(project(tmp_path, {"app/__init__.py": "", "app/views.py": "", "util.py": ""}))
    assert resolve(idx, ["app.views.home", "app.views"]).kind == "module" and resolve(idx, ["app.views.home"]).name == "app.views"
    assert resolve(idx, ["yaml"]) == Target("external", "yaml") and resolve(idx, ["yaml.loader"]) == Target("external", "yaml")
    assert resolve(idx, ["os.path"]).kind == "stdlib"
    assert resolve(idx, ["app.nothing"]).kind == "module"           # falls back to the package that does exist
    assert resolve(idx, ["util.helper"]).name == "util"


# ---------------------------------------------------------------- mapping import names to dependencies
def test_import_names_map_to_declared_dependencies():
    m = ImportMapper({"pyyaml", "pillow", "my-lib", "djangorestframework", "requests"})
    assert m.dist("yaml") == "pyyaml" and m.dist("PIL") == "pillow" and m.dist("rest_framework") == "djangorestframework"
    assert m.dist("my_lib") == "my-lib" and m.dist("requests") == "requests"      # same name, with _ for -
    assert m.dist("numpy") is None                                                  # not declared
    assert "yaml" in IMPORT_ALIASES


def test_installed_distribution_metadata_is_used_when_the_import_name_is_unusual(monkeypatch):
    import importlib.metadata as md
    monkeypatch.setattr(md, "packages_distributions", lambda: {"weirdname": ["Some_Dist"]})
    assert ImportMapper({"some-dist"}).dist("weirdname") == "some-dist"


def test_unmapped_third_party_imports_are_reported_not_silently_dropped(tmp_path):
    a = analyze(tmp_path, {**BASE, "app/v.py": "import numpy\nimport yaml\n"}, dep("pyyaml"))
    assert "numpy" in a.unmapped and any("numpy" in w and "could not be matched" in w for w in a.warnings)


# ---------------------------------------------------------------- routes
def routes(tmp_path, files, root="config.urls"):
    idx = discover(project(tmp_path, files))
    return [(p, r.target.name) for p, r in expand_routes(idx, root)]


def test_path_re_path_url_and_as_view(tmp_path):
    got = routes(tmp_path, {
        "config/urls.py": "from django.urls import path, re_path\nfrom django.conf.urls import url\nfrom app import views\nfrom app.views import home\n"
                          "urlpatterns = [path('a/', views.index), re_path(r'^b/$', home), url(r'^c/', views.Cls.as_view())]\n",
        "app/__init__.py": "", "app/views.py": "",
    })
    assert got == [("/a/", "app.views"), ("/b/", "app.views"), ("/c/", "app.views")]


def test_include_chains_join_prefixes_and_resolve_every_include_style(tmp_path):
    got = routes(tmp_path, {
        "config/urls.py": "from django.urls import path, include\nfrom app import urls as app_urls\nimport shop.urls\n"
                          "urlpatterns = [path('api/', include('api.urls')), path('app/', include(app_urls)), path('shop/', include(shop.urls)),"
                          " path('t/', include(('tup.urls', 'tup')))]\n",
        "api/__init__.py": "", "api/urls.py": "from django.urls import path, include\nfrom . import v\nurlpatterns = [path('v1/', include('api.v1')), path('ping/', v.ping)]\n",
        "api/v1.py": "from django.urls import path\nfrom . import v\nurlpatterns = [path('users/', v.users)]\n",
        "api/v.py": "",
        "app/__init__.py": "", "app/urls.py": "from django.urls import path\nfrom . import views\nurlpatterns = [path('x/', views.x)]\n", "app/views.py": "",
        "shop/__init__.py": "", "shop/urls.py": "from django.urls import path\nfrom . import views\nurlpatterns = [path('s/', views.s)]\n", "shop/views.py": "",
        "tup/__init__.py": "", "tup/urls.py": "from django.urls import path\nfrom . import views\nurlpatterns = [path('u/', views.u)]\n", "tup/views.py": "",
    })
    assert dict(got) == {"/api/v1/users/": "api.v", "/api/ping/": "api.v", "/app/x/": "app.views", "/shop/s/": "shop.views", "/t/u/": "tup.views"}


def test_decorated_views_and_urlpatterns_plus_equals(tmp_path):
    got = routes(tmp_path, {
        "config/urls.py": "from django.urls import path\nfrom django.contrib.auth.decorators import login_required\nfrom app import views\n"
                          "urlpatterns = [path('a/', login_required(views.secret))]\nurlpatterns += [path('b/', views.other)]\n",
        "app/__init__.py": "", "app/views.py": "",
    })
    assert got == [("/a/", "app.views"), ("/b/", "app.views")]


def test_drf_router_registrations_become_routes(tmp_path):
    got = routes(tmp_path, {
        "config/urls.py": "from django.urls import path, include\nfrom rest_framework.routers import DefaultRouter\nfrom app.views import UserViewSet, GroupViewSet\n"
                          "router = DefaultRouter()\nrouter.register('users', UserViewSet)\nrouter.register(r'groups', GroupViewSet)\n"
                          "urlpatterns = [path('api/', include(router.urls))]\n",
        "app/__init__.py": "", "app/views.py": "",
    })
    assert got == [("/api/users/", "app.views"), ("/api/groups/", "app.views")]


def test_unreadable_routes_are_skipped_not_guessed(tmp_path):
    got = routes(tmp_path, {
        "config/urls.py": "from django.urls import path\nfrom app import views\nPREFIX = 'x'\n"
                          "urlpatterns = [path(PREFIX + 'a/', views.ok), path('lam/', lambda r: None), path('nothing/')]\n",
        "app/__init__.py": "", "app/views.py": "",
    })
    assert got == [("/<computed>", "app.views")]      # the computed route is kept, labelled as such; the lambda and the view-less path are skipped


def test_include_cycles_terminate(tmp_path):
    got = routes(tmp_path, {
        "config/urls.py": "from django.urls import path, include\nurlpatterns = [path('a/', include('config.urls')), path('b/', include('other.urls'))]\n",
        "other/__init__.py": "", "other/urls.py": "from django.urls import path, include\nfrom . import v\nurlpatterns = [path('o/', include('config.urls')), path('v/', v.view)]\n",
        "other/v.py": "",
    })
    assert ("/b/v/", "other.v") in got and len(got) < 10


def test_admin_site_urls_resolve_to_the_third_party_package(tmp_path):
    idx = discover(project(tmp_path, {"config/urls.py": "from django.contrib import admin\nfrom django.urls import path\nurlpatterns = [path('admin/', admin.site.urls)]\n"}))
    [(full, r)] = expand_routes(idx, "config.urls")
    assert full == "/admin/" and r.target.kind == "external" and r.target.name == "django"


# ---------------------------------------------------------------- entry points and exposure levels
def test_a_package_imported_by_a_routed_view_is_web_exposed_with_its_path(tmp_path):
    a = analyze(tmp_path, {**BASE, "config/urls.py": "from django.urls import path\nfrom app import views\nurlpatterns = [path('go/', views.go)]\n",
                           "app/views.py": "import yaml\n"}, dep("pyyaml"))
    e = a.exposure("pyyaml")
    assert e["level"] == "web" and e["exposed"] is True
    assert e["path_labels"] == ["/go/", "app.views", "pyyaml"] and e["imported_by"] == ["app.views"]
    assert e["path"][0].startswith("entry:web:") and e["path"][-1] == "pkg:pyyaml"


def test_levels_command_test_none_and_unknown_direct_dependency(tmp_path):
    a = analyze(tmp_path, {
        **BASE,
        "app/management/__init__.py": "", "app/management/commands/__init__.py": "",
        "app/management/commands/job.py": "import yaml\n",
        "app/tasks.py": "import requests\n",
        "tests/__init__.py": "", "tests/test_x.py": "import flask\n",
        "app/dead.py": "import jinja2\n",
    }, dep("pyyaml"), dep("requests"), dep("flask"), dep("jinja2"), dep("never-imported"))
    assert level(a, "pyyaml") == "command" and a.exposure("pyyaml")["path_labels"][0] == "manage.py job"
    assert level(a, "requests") == "command"                                       # background tasks count as command level
    assert level(a, "flask") == "test"
    dead = a.exposure("jinja2")
    assert dead["level"] == "none" and dead["exposed"] is False and "app.dead" in dead["note"] and dead["imported_by"] == ["app.dead"]
    assert "no import of this package was found" in a.exposure("never-imported")["note"]


def test_the_strongest_level_wins(tmp_path):
    a = analyze(tmp_path, {
        **BASE, "config/urls.py": "from django.urls import path\nfrom app import views\nurlpatterns = [path('x/', views.x)]\n",
        "app/views.py": "import yaml\n", "app/management/__init__.py": "", "app/management/commands/__init__.py": "",
        "app/management/commands/j.py": "import yaml\nimport requests\n", "tests/__init__.py": "", "tests/test_a.py": "import yaml\nimport requests\nimport flask\n",
    }, dep("pyyaml"), dep("requests"), dep("flask"))
    assert (level(a, "pyyaml"), level(a, "requests"), level(a, "flask")) == ("web", "command", "test")


def test_settings_strings_installed_apps_and_autoloaded_modules_are_startup(tmp_path):
    a = analyze(tmp_path, {
        "config/__init__.py": "", "config/settings.py": "INSTALLED_APPS = ['app', 'thirdparty_app']\nROOT_URLCONF = 'config.urls'\n",
        "config/urls.py": "urlpatterns = []\n",
        "app/__init__.py": "", "app/models.py": "import yaml\n", "app/admin.py": "import requests\n", "app/other.py": "import flask\n",
    }, dep("pyyaml"), dep("requests"), dep("flask"), dep("thirdparty-app"))
    assert level(a, "pyyaml") == "startup" and level(a, "requests") == "startup"   # models.py and admin.py are auto-loaded
    assert level(a, "flask") == "none"                                              # app/other.py is not
    assert level(a, "thirdparty-app") == "startup"                                  # an installed app named by a string


def test_middleware_and_login_backends_run_on_web_requests(tmp_path):
    a = analyze(tmp_path, {
        "config/__init__.py": "", "config/settings.py": "MIDDLEWARE = ['corsheaders.middleware.CorsMiddleware', 'app.mw.Mine']\n"
                                                         "AUTHENTICATION_BACKENDS = ['ldapauth.Backend']\nROOT_URLCONF = 'config.urls'\n",
        "config/urls.py": "urlpatterns = []\n", "app/__init__.py": "", "app/mw.py": "import yaml\n",
    }, dep("django-cors-headers"), dep("pyyaml"), dep("ldapauth"))
    assert level(a, "django-cors-headers") == "web" and a.exposure("django-cors-headers")["path_labels"][0] == "middleware CorsMiddleware"
    assert level(a, "pyyaml") == "web"                                              # reached through the project's own middleware
    assert level(a, "ldapauth") == "web" and a.exposure("ldapauth")["path_labels"][0] == "login backend Backend"


def test_wsgi_and_manage_are_startup_entry_points(tmp_path):
    a = analyze(tmp_path, {"manage.py": "import yaml\n", "config/__init__.py": "", "config/wsgi.py": "import requests\n"}, dep("pyyaml"), dep("requests"))
    assert level(a, "pyyaml") == "startup" and level(a, "requests") == "startup"


def test_urlconf_imports_are_web_even_with_no_routes_listed(tmp_path):
    a = analyze(tmp_path, {**BASE, "config/urls.py": "from rest_framework import routers\nurlpatterns = []\n"}, dep("djangorestframework"))
    assert level(a, "djangorestframework") == "web"


def test_root_urlconf_is_guessed_when_the_setting_is_missing(tmp_path):
    a = analyze(tmp_path, {"config/__init__.py": "", "config/urls.py": "from django.urls import path, include\nurlpatterns = [path('s/', include('shop.urls'))]\n",
                           "shop/__init__.py": "", "shop/urls.py": "from django.urls import path\nfrom . import v\nurlpatterns = [path('x/', v.x)]\n", "shop/v.py": "import yaml\n"},
                dep("pyyaml"))
    assert a.exposure("pyyaml")["path_labels"][0] == "/s/x/"                        # shop.urls is included, config.urls is the root


def test_conditional_and_function_level_imports_still_count(tmp_path):
    a = analyze(tmp_path, {**BASE, "config/urls.py": "from django.urls import path\nfrom app import views\nurlpatterns = [path('z/', views.z)]\n",
                           "app/views.py": "def z(r):\n    if r:\n        import yaml\n    try:\n        import requests\n    except ImportError:\n        requests = None\n"},
                dep("pyyaml"), dep("requests"))
    assert level(a, "pyyaml") == "web" and level(a, "requests") == "web"            # we cannot tell if the branch runs, so we assume it can


def test_a_typing_only_import_does_not_expose_a_package(tmp_path):
    a = analyze(tmp_path, {**BASE, "config/urls.py": "from django.urls import path\nfrom app import views\nurlpatterns = [path('z/', views.z)]\n",
                           "app/views.py": "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import yaml\n"}, dep("pyyaml"))
    assert level(a, "pyyaml") == "none"


# ---------------------------------------------------------------- transitive dependencies
def test_transitive_exposure_follows_requires_edges_from_a_lock_file(tmp_path):
    files = {**BASE, "config/urls.py": "from django.urls import path\nfrom app import views\nurlpatterns = [path('a/', views.a)]\n", "app/views.py": "import requests\n"}
    a = analyze(tmp_path, files, dep("requests", requires=["urllib3", "idna"]), dep("urllib3", direct=False, requires=[]), dep("idna", direct=False, requires=[]),
                dep("orphan", direct=False, requires=[]))
    e = a.exposure("urllib3")
    assert e["level"] == "web" and e["path_labels"] == ["/a/", "app.views", "requests", "urllib3"]
    assert a.exposure("orphan")["level"] == "none" and "known dependency graph" in a.exposure("orphan")["note"]


def test_transitive_exposure_is_unknown_without_dependency_edges(tmp_path):
    a = analyze(tmp_path, {**BASE, "config/urls.py": "urlpatterns = []\n"}, dep("requests"), dep("urllib3", direct=False))
    assert a.exposure("urllib3") is None                                           # honest: nothing says what depends on it
    assert a.exposure("not-a-dependency") is None


def test_poetry_lock_supplies_the_requires_edges():
    lock = ('[[package]]\nname = "requests"\nversion = "2.31.0"\n[package.dependencies]\nurllib3 = ">=1.21"\nIdNA = "*"\n\n'
            '[[package]]\nname = "urllib3"\nversion = "2.0.0"\n')
    by = {d.name: d for d in parse_file("poetry.lock", lock.encode()).dependencies}
    assert by["requests"].requires == ["idna", "urllib3"] and by["urllib3"].requires == []


def test_no_entry_points_at_all_means_exposure_is_unknown_and_says_so(tmp_path):
    a = analyze(tmp_path, {"lib.py": "import yaml\n"}, dep("pyyaml"))
    assert a.exposure("pyyaml") is None and any("no Django entry points were found" in w for w in a.warnings)


# ---------------------------------------------------------------- the graph the UI draws
def test_render_contains_only_the_paths_to_vulnerable_packages_and_the_limitation(tmp_path):
    a = analyze(tmp_path, {**BASE, "config/urls.py": "from django.urls import path\nfrom app import views\nurlpatterns = [path('a/', views.a), path('b/', views.b)]\n",
                           "app/views.py": "import yaml\nimport requests\ndef a(r): pass\ndef b(r): pass\n", "app/dead.py": "import flask\n"},
                dep("pyyaml"), dep("requests"), dep("flask"))
    g = a.render({"pyyaml", "flask"})
    kinds = {n["id"]: n["kind"] for n in g["nodes"]}
    assert kinds["pkg:pyyaml"] == "vulnerable" and kinds["pkg:flask"] == "vulnerable" and "pkg:requests" not in kinds   # not vulnerable: not drawn
    assert kinds["mod:app.dead"] == "module"                                         # shown so "nothing reaches flask" can be checked by eye
    assert {("mod:app.dead", "pkg:flask")} <= {(link["source"], link["target"]) for link in g["links"]}
    assert g["limitation"] == LIMITATION and "Import-level" in g["limitation"] and "function calls" in g["limitation"]
    entry = next(n for n in g["nodes"] if n["kind"] == "entry")
    assert entry["level"] == "web"
    ids = {n["id"] for n in g["nodes"]}
    assert all(link["source"] in ids and link["target"] in ids for link in g["links"])    # no dangling edges


# ---------------------------------------------------------------- the risk factor
def risk_for(exposed):
    """Risk of one fixed finding (CVSS 9.8, no other signals) at a given exposure."""
    d = dep("alpha")
    m = Match(id="CVE-2030-0001", aliases=[], dependency=d, confidence="confirmed", evidence=[], verdicts=[], advisories=[], fixed_versions=["1.5"], version="1.0")
    return compute_risk(m, nvd={"CVE-2030-0001": {"cvss": {"v31": {"score": 9.8}}}}, kev={}, epss={}, fixed_version="1.5", major_bump=False, cfg=CFG, exposed=exposed)


@pytest.mark.parametrize("lvl,factor", [("web", 1.0), ("startup", 0.6), ("command", 0.3), ("test", 0.0), ("none", 0.0)])
def test_exposure_levels_set_the_factor_from_config(lvl, factor):
    f = next(x for x in risk_for(lvl)["factors"] if x["name"] == "exposure")
    assert CFG["risk"]["exposure_levels"][lvl] == factor
    assert f["contribution"] == pytest.approx(100 * f["weight"] * factor, abs=0.01)


def test_more_reachable_means_higher_risk_and_unknown_is_dropped():
    score = {lv: risk_for(lv)["score"] for lv in ("web", "startup", "command", "none")}
    assert score["web"] > score["startup"] > score["command"] > score["none"]
    assert "exposure" not in [f["name"] for f in risk_for(None)["factors"]]
    assert risk_for(True)["score"] == score["web"] and risk_for(False)["score"] == score["none"]   # True / False still mean web / none


# ---------------------------------------------------------------- end to end on the sample Django app
EXPECTED_LEVEL = {"pyyaml": "web", "requests": "web", "jinja2": "web", "pyspark": "command", "six": "startup", "flask": "none", "django": "web"}


@pytest.fixture(scope="module")
def sample_scan():
    deps = (APP / "requirements.txt").read_bytes()
    return scan_files([("requirements.txt", deps)], DataBundle(SAMPLE / "snapshot"), project_dir=APP)


def test_sample_app_levels_match_the_table_in_its_readme():
    deps = parse_file("requirements.txt", (APP / "requirements.txt").read_bytes()).dependencies
    a = analyze_project(APP, deps)
    assert {n: level(a, n) for n in EXPECTED_LEVEL} == EXPECTED_LEVEL
    assert a.exposure("pyyaml")["path_labels"] == ["/login/", "accounts.views", "pyyaml"]
    assert a.exposure("jinja2")["path_labels"] == ["/login/", "accounts.views", "utils.helpers", "jinja2"]
    assert a.exposure("flask")["imported_by"] == ["utils.legacy"]
    assert a.warnings == []                                                          # every import maps to a declared dependency


# Expected ranking on the sample app (risk, highest first), and why it differs from the no-graph ranking (#6 of 15 in
# tests/test_known_sample.py's order for pyspark CVE-2023-22946, etc.):
#   * the KEV-listed pyspark finding stays first even though only a command reaches pyspark: a known-exploited
#     vulnerability is not pushed down by an import-level guess;
#   * pyyaml and requests, reached by web routes, rise above the command-only pyspark findings that scored higher before;
#   * the flask findings, whose only importer is dead code, fall to the bottom.
EXPECTED_ORDER = [
    ("pyspark", "CVE-2022-33891"), ("pyspark", "CVE-2023-32007"),
    ("pyyaml", "CVE-2020-14343"), ("pyyaml", "CVE-2020-1747"), ("pyyaml", "CVE-2019-20477"),
    ("pyspark", "CVE-2023-22946"),
    ("requests", "CVE-2024-35195"), ("requests", "CVE-2024-47081"), ("pyyaml", "PYSEC-2020-195"), ("requests", "CVE-2026-25645"),
    ("pyspark", "CVE-2025-55039"), ("pyspark", "CVE-2026-32773"),
    ("flask", "CVE-2023-30861"), ("pyspark", "CVE-2022-31777"), ("flask", "CVE-2026-27205"),
]


def test_sample_app_ranking(sample_scan):
    assert [(f["package"], f["id"]) for f in sample_scan["findings"]] == EXPECTED_ORDER


def test_exposure_changes_the_ranking_in_the_documented_directions(sample_scan):
    before = scan_files([("requirements.txt", (SAMPLE / "requirements.txt").read_bytes())], DataBundle(SAMPLE / "snapshot"))
    old = {f["key"]: f["risk"]["score"] for f in before["findings"]}
    new = {f["key"]: f for f in sample_scan["findings"]}
    for k, f in new.items():
        lvl = f["exposure"]["level"]
        if lvl == "web":
            assert f["risk"]["score"] > old[k], k           # web-reached findings rise
        elif lvl in ("none", "command"):
            assert f["risk"]["score"] < old[k], k           # unreached or command-only findings fall
    assert sample_scan["findings"][0]["kev"] is True        # ...but a KEV finding is still first


def test_findings_carry_the_exposure_object_and_the_factor_is_in_the_risk_table(sample_scan):
    for f in sample_scan["findings"]:
        e = f["exposure"]
        assert set(e) == {"level", "exposed", "path", "path_labels", "imported_by", "note"} and e["exposed"] == (e["level"] == "web")
        assert "exposure" in [x["name"] for x in f["risk"]["factors"]] and not any("exposure factor dropped" in n for n in f["risk"]["notes"])
    top = sample_scan["findings"][2]
    assert top["exposure"]["path_labels"][0] == "/login/" and top["risk"]["factors"][-1]["name"] == "exposure"


def test_graph_in_the_result_draws_every_vulnerable_package(sample_scan):
    g = sample_scan["graph"]
    vuln = {n["label"] for n in g["nodes"] if n["kind"] == "vulnerable"}
    assert vuln == {"pyyaml", "requests", "pyspark", "flask"}                       # the four with findings (jinja2 and six have none)
    assert g["stats"]["web_entry_points"] == 7 and g["limitation"] == LIMITATION


def test_without_a_project_nothing_changes_and_exposure_is_absent(data_dir):
    r = scan_files([("requirements.txt", b"alpha==1.0\n")], DataBundle(data_dir))
    assert r["findings"][0]["exposure"] is None and r["graph"] is None
    assert "exposure" not in [x["name"] for x in r["findings"][0]["risk"]["factors"]]            # dropped, weights renormalised


def test_other_ecosystems_get_a_warning_not_a_fake_exposure(tmp_path, data_dir):
    """An npm finding next to a Django project: the graph is Python-only, so that finding has no exposure, and it says so."""
    import zipfile

    from depscan.data.osv import build_osv_index
    adv = {"id": "GHSA-npm-1", "aliases": ["CVE-2030-9"], "summary": "bad", "modified": "2030-01-01T00:00:00Z",
           "affected": [{"package": {"ecosystem": "npm", "name": "left-pad"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}]}
    z = data_dir / "npm.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("a.json", json.dumps(adv))
    build_osv_index(z, data_dir / "osv" / "npm.index.json", "npm")
    p = project(tmp_path, {**BASE, "config/urls.py": "urlpatterns = []\n"})
    pkg = json.dumps({"dependencies": {"left-pad": "1.0.0"}}).encode()
    r = scan_files([("package.json", pkg), ("requirements.txt", b"alpha==1.0\n")], DataBundle(data_dir), project_dir=p)
    by = {f["package"]: f for f in r["findings"]}
    assert by["left-pad"]["exposure"] is None and by["alpha"]["exposure"] is not None
    assert any("covers Python (Django) packages only" in w for w in r["warnings"])


# ---------------------------------------------------------------- safety
def test_the_analysis_never_runs_or_modifies_project_code(tmp_path):
    marker = tmp_path / "RAN"
    p = project(tmp_path / "proj", {**BASE, "config/urls.py": "urlpatterns = []\n",
                                    "app/boom.py": f"open(r'{marker}', 'w').write('x')\nraise SystemExit('executed!')\nimport yaml\n"})
    before = {f.relative_to(p): hashlib.sha256(f.read_bytes()).hexdigest() for f in p.rglob("*") if f.is_file()}
    a = analyze_project(p, [dep("pyyaml")])
    assert a.exposure("pyyaml")["level"] == "none"                                   # it was READ (the import is seen) ...
    assert not marker.exists()                                                       # ... but never executed
    assert {f.relative_to(p): hashlib.sha256(f.read_bytes()).hexdigest() for f in p.rglob("*") if f.is_file()} == before


def test_deterministic(tmp_path):
    files = {**BASE, "config/urls.py": "from django.urls import path\nfrom app import v\nurlpatterns = [path('a/', v.a)]\n", "app/v.py": "import yaml\nimport requests\n"}
    a = analyze(tmp_path, files, dep("pyyaml"), dep("requests"))
    assert a.render({"pyyaml", "requests"}) == a.render({"pyyaml", "requests"})


# ---------------------------------------------------------------- reports and CLI
def test_reports_show_exposure_and_carry_the_limitation(sample_scan):
    from depscan.report import render_html, render_markdown
    md, page = render_markdown(sample_scan), render_html(sample_scan)
    for text in (md, page):
        assert "Exposure: reachable from a web request. Path: /login/ → accounts.views → pyyaml." in text.replace("&rarr;", "→")
        assert "Import-level analysis of a Django project" in text
    assert "Exposure: not reached from any entry point." in md and "utils.legacy" in md


def test_cli_uses_a_folder_with_manage_py_automatically(tmp_path, capsys):
    import shutil

    from depscan.__main__ import main
    app = tmp_path / "app"
    shutil.copytree(APP, app)
    out = tmp_path / "r.json"
    assert main(["scan", str(app), "--data-dir", str(SAMPLE / "snapshot"), "--offline", "--review-db", str(tmp_path / "x.sqlite"), "--out", str(out)]) == 0
    r = json.loads(out.read_text())
    assert r["graph"] is not None and all(f["exposure"] is not None for f in r["findings"])
    assert main(["scan", str(app / "requirements.txt"), "--data-dir", str(SAMPLE / "snapshot"), "--offline", "--review-db", str(tmp_path / "x.sqlite"), "--out", str(out)]) == 0
    assert json.loads(out.read_text())["graph"] is None                              # a file alone: no project analysed, nothing guessed
    assert main(["scan", str(app / "requirements.txt"), "--project-dir", str(app), "--data-dir", str(SAMPLE / "snapshot"), "--offline",
                 "--review-db", str(tmp_path / "x.sqlite"), "--out", str(out)]) == 0
    assert json.loads(out.read_text())["graph"] is not None                          # ...unless --project-dir says where it is


def test_contract_with_the_frontend_types(sample_scan):
    import re
    types = (Path(__file__).resolve().parent.parent / "frontend" / "src" / "lib" / "types.ts").read_text("utf-8")
    kinds = set(re.search(r"kind: (.*)", re.search(r"export interface GraphNode \{(.*?)\n\}", types, re.S).group(1)).group(1).replace("'", "").replace(" ", "").split("|"))
    for n in sample_scan["graph"]["nodes"]:
        assert {"id", "label", "kind"} <= set(n) and n["kind"] in kinds
    exp = re.search(r"exposure: \{(.*?)\} \| null", types, re.S).group(1)
    for key in ("exposed", "level", "path", "path_labels", "imported_by", "note"):
        assert key in exp
    levels = set(re.search(r"export type ExposureLevel = (.*)", types).group(1).replace("'", "").replace(" ", "").split("|"))
    assert {f["exposure"]["level"] for f in sample_scan["findings"]} <= levels


def test_package_init_modules_are_run_with_their_children_but_are_not_entry_points_themselves(tmp_path):
    a = analyze(tmp_path, {
        **BASE,
        "tests/__init__.py": "import yaml\n", "tests/test_x.py": "",
        "app/management/__init__.py": "", "app/management/commands/__init__.py": "import requests\n", "app/management/commands/job.py": "",
        "config/urls.py": "from django.urls import path\nfrom app import views\nurlpatterns = [path('v/', views.v)]\n",
        "app/views.py": "", "app/__init__.py": "import flask\n",
    }, dep("pyyaml"), dep("requests"), dep("flask"))
    assert level(a, "pyyaml") == "test" and level(a, "requests") == "command"        # imports inside an __init__ are reached
    assert level(a, "flask") == "web"                                                # app/__init__.py runs when app.views is imported
    labels = set(a.labels[n] for n in a.entry_level)
    assert "tests (tests)" not in labels and "manage.py commands" not in labels     # the packages themselves are not entry points
    assert "manage.py job" in labels and "tests (tests.test_x)" in labels
