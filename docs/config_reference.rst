Configuration Reference
=========================

.. include:: config_flask.rst
   
Flask-Session configuration values
----------------------------------

These are specific to Flask-Session.

.. py:data:: SESSION_TYPE

   Specifies which type of session interface to use. Built-in session types:

   - **redis**: RedisSessionInterface
   - **memcached**: MemcachedSessionInterface
   - **filesystem**: FileSystemSessionInterface (Deprecated in 0.7.0, will be removed in 1.0.0 in favor of CacheLibSessionInterface)
   - **cachelib**: CacheLibSessionInterface
   - **mongodb**: MongoDBSessionInterface
   - **sqlalchemy**: SqlAlchemySessionInterface
   - **dynamodb**: DynamoDBSessionInterface

.. py:data:: SESSION_PERMANENT

   Whether use permanent session or not.
   
   Default: ``True``

.. py:data:: SESSION_USE_SIGNER

   Whether sign the session cookie sid or not, if set to ``True``, you have to set :attr:`flask.Flask.secret_key`.

   .. note::
       This feature is historical and generally only relevant if you are using client-side sessions ie. not Flask-Session. SESSION_ID_LENGTH provides the relevant entropy for session identifiers.
   
   Default: ``False``

   .. deprecated:: 0.7.0

.. py:data:: SESSION_KEY_PREFIX

   A prefix that is added before all session keys. This makes it easier to use the same backend storage server for different apps.
   
   Default: ``'session:'``

.. py:data:: SESSION_ID_LENGTH

   The length of the session identifier in bytes (of entropy).
   
   Default: ``32``

   .. versionadded:: 0.6.0

.. py:data:: SESSION_SERIALIZATION_FORMAT

   The serialization format to use. Can be `'msgpack'`` or `'json'`. Set to `'msgpack'`` for a more efficient serialization format. Set to `'json'`` for a human-readable format.

   Default: ``'msgpack'``

   .. versionadded:: 0.7.0

.. py:data:: SESSION_READONLY_ENDPOINTS

   A sequence of rules selecting Flask endpoints whose requests must treat the
   session as read-only. Requests handled by a matching endpoint may still read
   session data, but any attempt to modify it raises
   :class:`~flask_session.base.ReadOnlySessionError`, and the response is never
   persisted: no backend upsert, deletion or TTL refresh takes place and no
   ``Set-Cookie`` header is issued. The response still carries
   ``Vary: Cookie`` when the session was accessed.

   Each rule can be one of:

   - an endpoint name string (``"api.profile"``); strings containing wildcards
     are interpreted as ``fnmatch`` patterns (``"api.*"``);
   - a compiled regular expression, matched with :meth:`re.Pattern.fullmatch`;
   - a callable taking the endpoint name and returning a truthy value.

   The error message names both the endpoint and the specific rule that blocked
   the write, making the offending rule easy to locate. Endpoints not selected
   by any rule keep their normal read/write behavior.

   .. code-block:: python

      import re

      app.config["SESSION_READONLY_ENDPOINTS"] = (
          "api.health",
          re.compile(r"^api\.reports\..+"),
          lambda endpoint: endpoint is not None and endpoint.startswith("metrics."),
      )

   Default: ``()`` (all endpoints are writable)

.. deprecated:: 0.7.0
    ``SESSION_USE_SIGNER``

.. versionadded:: 0.7.0
    ``SESSION_SERIALIZATION_FORMAT``

.. versionadded:: 0.6.0
    ``SESSION_ID_LENGTH``


Storage configuration values
----------------------------


Redis
~~~~~~~~~~~~~~~~~~~~~~~

.. py:data:: SESSION_REDIS

   A ``redis.Redis`` instance.
   
   Default: Instance connected to ``127.0.0.1:6379``


Memcached
~~~~~~~~~~~~~~~~~~~~~~~

.. py:data:: SESSION_MEMCACHED

   A ``memcache.Client`` instance.
   
   Default: Instance connected to ``127.0.0.1:6379``


FileSystem
~~~~~~~~~~~~~~~~~~~~~~~

.. py:data:: SESSION_FILE_DIR

   The directory where session files are stored.
   
   Default: ``flask_session`` directory under current working directory.

   .. deprecated:: 0.7.0

.. py:data:: SESSION_FILE_THRESHOLD
    
   The maximum number of items the session stores before it starts deleting some.
   
   Default: ``500``

   .. deprecated:: 0.7.0

.. py:data:: SESSION_FILE_MODE
    
   The file mode wanted for the session files.
   
   Default: ``0600``

   .. deprecated:: 0.7.0

CacheLib
~~~~~~~~~~~~~~~~~~~~~~~
.. py:data:: SESSION_CACHELIB

   Any valid `cachelib backend <https://cachelib.readthedocs.io/en/stable/>`_. This allows you maximum flexibility in choosing the cache backend and it's configuration.
   
   The following would set a cache directory called "flask_session" and a threshold of 500 items before it starts deleting some.
   
   .. code-block:: python

      app.config['SESSION_CACHELIB'] = FileSystemCache(cache_dir='flask_session', threshold=500)
   
   .. important::
   
      A ``default_timeout`` set in any of the ``CacheLib`` backends will be overrode by the ``PERMANENT_SESSION_LIFETIME`` when each stored session's expiry is set.
   
   Default: ``FileSystemCache`` in ``./flask_session`` directory.

MongoDB
~~~~~~~~~~~~~~~~~~~~~~~

.. py:data:: SESSION_MONGODB

   A ``pymongo.MongoClient`` instance.
   
   Default: Instance connected to ``127.0.0.1:27017``

.. py:data:: SESSION_MONGODB_DB
    
   The MongoDB database you want to use.
   
   Default: ``'flask_session'``

.. py:data:: SESSION_MONGODB_COLLECT
    
   The MongoDB collection you want to use.
   
   Default: ``'sessions'``


SqlAlchemy
~~~~~~~~~~~~~~~~~~~~~~~

.. py:data:: SESSION_SQLALCHEMY

   A ``flask_sqlalchemy.SQLAlchemy`` instance whose database connection URI is configured using the ``SQLALCHEMY_DATABASE_URI`` parameter.
   
   Must be set in flask_sqlalchemy version 3.0 or higher.

.. py:data:: SESSION_SQLALCHEMY_TABLE
    
   The name of the SQL table you want to use.
   
   Default: ``'sessions'``

.. py:data:: SESSION_SQLALCHEMY_SEQUENCE
    
   The name of the sequence you want to use for the primary key.
   
   Default: ``None``

.. py:data:: SESSION_SQLALCHEMY_SCHEMA
    
   The name of the schema you want to use.
   
   Default: ``None``

.. py:data:: SESSION_SQLALCHEMY_BIND_KEY
    
   The name of the bind key you want to use.
   
   Default: ``None``

.. py:data:: SESSION_CLEANUP_N_REQUESTS

   Only applicable to non-TTL backends.
   
   The average number of requests after which Flask-Session will perform a session cleanup. This involves removing all session data that is older than ``PERMANENT_SESSION_LIFETIME``. Using the app command ``flask session_cleanup`` instead is preferable.
   
   Default: ``None``

Dynamodb
~~~~~~~~~~~~~~~~~~~~~~~

.. py:data:: SESSION_DYNAMODB
   
      A ``boto3.resource`` instance.
      
      Default: Instance connected to ``'localhost:8000'``

.. py:data:: SESSION_DYNAMODB_TABLE_NAME

      The name of the table you want to use.
      
      Default: ``'Sessions'``

.. py:data:: SESSION_DYNAMODB_TABLE_EXISTS

      By default it will create a new table with the TTL setting activated unless you set this parameter to ``True``, then it assumes that the table already exists.
      
      Default: ``False``

.. deprecated:: 0.7.0

   ``SESSION_FILE_DIR``, ``SESSION_FILE_THRESHOLD``, ``SESSION_FILE_MODE``. Use ``SESSION_CACHELIB`` instead.

.. versionadded:: 0.7.0
    ``SESSION_CLEANUP_N_REQUESTS``

.. versionadded:: 0.6.0
    ``SESSION_SQLALCHEMY_BIND_KEY``, ``SESSION_SQLALCHEMY_SCHEMA``, ``SESSION_SQLALCHEMY_SEQUENCE``
