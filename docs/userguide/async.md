---
title: Asynchronous views
description: Using PermissionRequiredMixin and LoginRequiredMixin with asynchronous class-based views.
---

# Asynchronous views

`guardian.mixins.PermissionRequiredMixin` and
`guardian.mixins.LoginRequiredMixin` work with asynchronous class-based
views. Django detects a view as asynchronous when all of its HTTP handlers
(`get()`, `post()`, ...) are coroutines. When that is the case, the mixins
run their asynchronous counterpart instead of the synchronous one.

!!! note
    Asynchronous class-based views require Django >= 4.2.

Synchronous views are unaffected: the permission check keeps using
`check_permissions()` and `get_permission_object()` exactly as before, and
the only addition on that path is a single flag check in `dispatch()`.

## Basic usage

Nothing special is required. Declare the handlers as coroutines and the
mixin does the rest:

```python
from django.http import HttpResponse
from django.views.generic import View

from guardian.mixins import PermissionRequiredMixin


class PostView(PermissionRequiredMixin, View):
    permission_required = 'testapp.change_post'
    raise_exception = True

    async def get(self, request, *args, **kwargs):
        return HttpResponse('some html')
```

By default, the object to check the permission against is resolved by
`aget_permission_object()`, which runs the synchronous
`get_permission_object()` in a thread. That is, `permission_object`,
`get_object()` and `object` are honoured as usual.

## Login required

`LoginRequiredMixin` needs nothing beyond the same rule. An anonymous user
is redirected to the login page before the handler runs, and the lazy
`request.user` is never read in the event loop:

```python
from django.http import HttpResponse
from django.views.generic import View

from guardian.mixins import LoginRequiredMixin


class SecretView(LoginRequiredMixin, View):
    async def get(self, request, *args, **kwargs):
        return HttpResponse('some html')
```

## Fetching the object with the asynchronous ORM

To avoid the thread hop and use the asynchronous ORM API, override
`aget_permission_object()`:

```python
class PostView(PermissionRequiredMixin, View):
    permission_required = 'testapp.change_post'
    raise_exception = True

    async def aget_permission_object(self):
        return await Post.objects.aget(slug=self.kwargs['slug'])

    async def get(self, request, *args, **kwargs):
        return HttpResponse('some html')
```

An `async def get_object()` or an `async def get_permission_object()` on the
view is awaited as well, so this works too:

```python
class PostView(PermissionRequiredMixin, View):
    permission_required = 'testapp.change_post'

    async def get_object(self):
        return await Post.objects.aget(slug=self.kwargs['slug'])

    async def get(self, request, *args, **kwargs):
        return HttpResponse('some html')
```

## Asynchronous counterparts

Every `PermissionRequiredMixin` method on the dispatch path has an
`a`-prefixed sister method, following the naming convention used by Django
itself (`aget()`, `acreate()`, ...):

| Synchronous               | Asynchronous               |
|---------------------------|----------------------------|
| `get_permission_object()` | `aget_permission_object()` |
| `check_permissions()`     | `acheck_permissions()`     |
| `dispatch()`              | `adispatch()`              |

`LoginRequiredMixin` has no such counterpart to override: its asynchronous
path only applies `login_required()` before chaining on to the next
`dispatch()`, so `login_url` and `redirect_field_name` are the only knobs.

`get_required_permissions()`, `get_object_permission_denied_message()` and
`on_permission_check_fail()` have no asynchronous counterpart: they are all
called from a single worker thread, so they may run queries.

If you override `check_permissions()`, override `acheck_permissions()` as
well; asynchronous views do not call the synchronous one.

## Hiding inaccessible records

A detail page usually must not reveal whether a record that the current user
cannot access even exists. Combine `LoginRequiredMixin` with
`PermissionRequiredMixin` and set `return_404 = True`:

```python
from django.http import Http404, HttpResponse
from django.views.generic import DetailView

from guardian.mixins import LoginRequiredMixin, PermissionRequiredMixin


class PostDetailView(LoginRequiredMixin, PermissionRequiredMixin, DetailView):
    model = Post
    permission_required = "testapp.view_post"
    return_404 = True

    async def aget_permission_object(self):
        try:
            return await Post.objects.aget(pk=self.kwargs["pk"])
        except Post.DoesNotExist:
            raise Http404

    async def get(self, request, *args, **kwargs):
        post = await self.aget_permission_object()
        return HttpResponse(post.title)
```

The external responses then match the synchronous view exactly:

- An anonymous request is redirected to the login page (the per-application
  `login_url`, with the current path in `redirect_field_name`), whether or not
  the record exists.
- An authenticated user without the permission gets the same 404 as a request
  for a record that does not exist, so existence cannot be probed.
- An authorized user reaches the handler normally.

The two authenticated denials stay distinguishable internally: a missing
record raises `Http404` while a permission failure calls
`on_permission_check_fail()` with the resolved object before the 404 is
returned. The synchronous `get_object()` path is covered as well, since
`aget_permission_object()` runs it in a worker thread by default and lets its
`Http404` propagate to the same 404 response.

## Limitations

- Django's generic views (`DetailView`, `ListView`, ...) provide synchronous
  handlers by default. They use the mixin's synchronous path unless every
  effective HTTP handler is overridden with a coroutine.
- `PermissionListMixin` has no asynchronous support yet.
- On Django 4.1 and older the synchronous path is used even for
  asynchronous views. Responses for a disallowed HTTP method only became
  awaitable in Django 4.1.2, and 4.1 is end of life, so the floor is 4.2.
