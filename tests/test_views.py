from __future__ import annotations

import flask_restful
import hiro
import pytest
from flask import request
from flask.views import MethodView, View


def test_pluggable_views(extension_factory):
    app, limiter = extension_factory(default_limits=["1/hour"])

    class Va(View):
        methods = ["GET", "POST"]
        decorators = [limiter.limit("2/second")]

        def dispatch_request(self):
            return request.method.lower()

    class Vb(View):
        methods = ["GET"]
        decorators = [limiter.limit("1/second, 3/minute")]

        def dispatch_request(self):
            return request.method.lower()

    class Vc(View):
        methods = ["GET"]

        def dispatch_request(self):
            return request.method.lower()

    app.add_url_rule("/a", view_func=Va.as_view("a"))
    app.add_url_rule("/b", view_func=Vb.as_view("b"))
    app.add_url_rule("/c", view_func=Vc.as_view("c"))
    with hiro.Timeline().freeze() as timeline:
        with app.test_client() as cli:
            assert 200 == cli.get("/a").status_code
            assert 200 == cli.get("/a").status_code
            assert 429 == cli.post("/a").status_code
            assert 200 == cli.get("/b").status_code
            timeline.forward(1)
            assert 200 == cli.get("/b").status_code
            timeline.forward(1)
            assert 200 == cli.get("/b").status_code
            timeline.forward(1)
            assert 429 == cli.get("/b").status_code
            assert 200 == cli.get("/c").status_code
            assert 429 == cli.get("/c").status_code


def test_pluggable_method_views(extension_factory):
    app, limiter = extension_factory(default_limits=["1/hour"])

    class Va(MethodView):
        decorators = [limiter.limit("2/second")]

        def get(self):
            return request.method.lower()

        def post(self):
            return request.method.lower()

    class Vb(MethodView):
        decorators = [limiter.limit("1/second, 3/minute")]

        def get(self):
            return request.method.lower()

    class Vc(MethodView):
        def get(self):
            return request.method.lower()

    class Vd(MethodView):
        decorators = [limiter.limit("1/minute", methods=["get"])]

        def get(self):
            return request.method.lower()

        def post(self):
            return request.method.lower()

    app.add_url_rule("/a", view_func=Va.as_view("a"))
    app.add_url_rule("/b", view_func=Vb.as_view("b"))
    app.add_url_rule("/c", view_func=Vc.as_view("c"))
    app.add_url_rule("/d", view_func=Vd.as_view("d"))

    with hiro.Timeline().freeze() as timeline:
        with app.test_client() as cli:
            assert 200 == cli.get("/a").status_code
            assert 200 == cli.get("/a").status_code
            assert 429 == cli.get("/a").status_code
            assert 429 == cli.post("/a").status_code
            assert 200 == cli.get("/b").status_code
            timeline.forward(1)
            assert 200 == cli.get("/b").status_code
            timeline.forward(1)
            assert 200 == cli.get("/b").status_code
            timeline.forward(1)
            assert 429 == cli.get("/b").status_code
            assert 200 == cli.get("/c").status_code
            assert 429 == cli.get("/c").status_code
            assert 200 == cli.get("/d").status_code
            assert 429 == cli.get("/d").status_code
            assert 200 == cli.post("/d").status_code
            assert 429 == cli.post("/d").status_code
            timeline.forward(3600)
            assert 200 == cli.post("/d").status_code


def test_flask_restful_resource(extension_factory):
    app, limiter = extension_factory(default_limits=["1/hour"])
    api = flask_restful.Api(app)

    class Va(flask_restful.Resource):
        decorators = [limiter.limit("2/second")]

        def get(self):
            return request.method.lower()

        def post(self):
            return request.method.lower()

    class Vb(flask_restful.Resource):
        decorators = [limiter.limit("1/second, 3/minute")]

        def get(self):
            return request.method.lower()

    class Vc(flask_restful.Resource):
        def get(self):
            return request.method.lower()

    class Vd(flask_restful.Resource):
        decorators = [
            limiter.limit("2/second", methods=["GET"]),
            limiter.limit("1/second", methods=["POST"]),
        ]

        def get(self):
            return request.method.lower()

        def post(self):
            return request.method.lower()

    api.add_resource(Va, "/a")
    api.add_resource(Vb, "/b")
    api.add_resource(Vc, "/c")
    api.add_resource(Vd, "/d")

    with hiro.Timeline().freeze() as timeline:
        with app.test_client() as cli:
            assert 200 == cli.get("/a").status_code
            assert 200 == cli.get("/a").status_code
            assert 429 == cli.get("/a").status_code
            assert 429 == cli.post("/a").status_code
            assert 200 == cli.get("/b").status_code
            assert 200 == cli.get("/d").status_code
            assert 200 == cli.get("/d").status_code
            assert 429 == cli.get("/d").status_code
            assert 200 == cli.post("/d").status_code
            assert 429 == cli.post("/d").status_code
            timeline.forward(1)
            assert 200 == cli.get("/b").status_code
            timeline.forward(1)
            assert 200 == cli.get("/b").status_code
            timeline.forward(1)
            assert 429 == cli.get("/b").status_code
            assert 200 == cli.get("/c").status_code
            assert 429 == cli.get("/c").status_code


@pytest.mark.xfail
def test_flask_restx_resource(extension_factory):
    import flask_restx

    app, limiter = extension_factory()
    api = flask_restx.Api(app)
    ns = api.namespace("test")

    @ns.route("/a")
    class Va(flask_restx.Resource):
        decorators = [limiter.limit("2/second", per_method=True)]

        def get(self):
            return request.method.lower()

        def post(self):
            return request.method.lower()

    with hiro.Timeline().freeze() as timeline:
        with app.test_client() as cli:
            assert 200 == cli.get("/test/a").status_code
            assert 200 == cli.get("/test/a").status_code
            assert 200 == cli.post("/test/a").status_code
            assert 200 == cli.post("/test/a").status_code
            assert 429 == cli.get("/test/a").status_code
            assert 429 == cli.post("/test/a").status_code
            timeline.forward(1)
            assert 200 == cli.get("/test/a").status_code
            assert 200 == cli.post("/test/a").status_code


def _shared_write_resource_app(extension_factory):
    app, limiter = extension_factory(
        key_func=lambda: request.headers.get("X-Identity", "anonymous"),
        headers_enabled=True,
    )
    # ``scope`` pins the limit to a shared bucket named after the business
    # resource instead of the default per-endpoint bucket, so both routes
    # drawing on "resource-write" consume the same quota.
    shared_write_limit = limiter.shared_limit(
        "2/minute", scope="resource-write", methods=["post", "put"]
    )

    class ResourceView(MethodView):
        # reads keep the default scoping (the endpoint), so each route counts
        # independently of the other and of the shared write scope.
        decorators = [shared_write_limit, limiter.limit("1/minute", methods=["get"])]

        def get(self):
            return "read"

        def post(self):
            return "write"

        def put(self):
            return "write"

    app.add_url_rule(
        "/resource/primary", view_func=ResourceView.as_view("resource_primary")
    )
    app.add_url_rule(
        "/resource/secondary", view_func=ResourceView.as_view("resource_secondary")
    )

    return app


def test_method_view_shared_write_limit_alternating_same_identity(extension_factory):
    """Writes from one identity alternate between two routes of the same
    resource and must exhaust the single shared quota."""
    app = _shared_write_resource_app(extension_factory)

    with hiro.Timeline().freeze():
        with app.test_client() as cli:
            identity = {"X-Identity": "writer-1"}
            resp = cli.post("/resource/primary", headers=identity)
            assert 200 == resp.status_code
            assert "1" == resp.headers["X-RateLimit-Remaining"]
            resp = cli.put("/resource/secondary", headers=identity)
            assert 200 == resp.status_code
            assert "0" == resp.headers["X-RateLimit-Remaining"]
            # the decisive assertions: an implementation that only forges
            # identical X-RateLimit-* headers without sharing the underlying
            # storage key would still allow these writes through.
            assert 429 == cli.post("/resource/secondary", headers=identity).status_code
            assert 429 == cli.put("/resource/primary", headers=identity).status_code


def test_method_view_shared_write_limit_is_scoped_per_identity(extension_factory):
    """The shared scope is combined with the limiter key, so another identity
    gets its own "resource-write" budget on the same two routes."""
    app = _shared_write_resource_app(extension_factory)

    with hiro.Timeline().freeze():
        with app.test_client() as cli:
            first = {"X-Identity": "writer-1"}
            second = {"X-Identity": "writer-2"}
            assert 200 == cli.post("/resource/primary", headers=first).status_code
            assert 200 == cli.put("/resource/secondary", headers=first).status_code
            assert 429 == cli.post("/resource/primary", headers=first).status_code
            # writer-2 shares the scope name but not writer-1's count
            assert 200 == cli.post("/resource/secondary", headers=second).status_code
            assert 200 == cli.put("/resource/primary", headers=second).status_code
            assert 429 == cli.post("/resource/secondary", headers=second).status_code


def test_method_view_read_limits_independent_of_shared_write_scope(extension_factory):
    """Reads fall back to the default endpoint scope: they are not charged
    against the shared write quota and are counted per route."""
    app = _shared_write_resource_app(extension_factory)

    with hiro.Timeline().freeze():
        with app.test_client() as cli:
            identity = {"X-Identity": "writer-1"}
            # exhaust the shared write budget first
            assert 200 == cli.post("/resource/primary", headers=identity).status_code
            assert 200 == cli.put("/resource/secondary", headers=identity).status_code
            assert 429 == cli.post("/resource/primary", headers=identity).status_code
            # reads draw from their own per-endpoint limit, not the shared scope
            assert 200 == cli.get("/resource/primary", headers=identity).status_code
            assert 200 == cli.get("/resource/secondary", headers=identity).status_code
            # each endpoint counts reads independently of the other
            assert 429 == cli.get("/resource/primary", headers=identity).status_code
            assert 429 == cli.get("/resource/secondary", headers=identity).status_code
