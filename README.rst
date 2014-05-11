=======================================
Installing and Using Python Keyring Lib
=======================================

.. contents:: **Table of Contents**

---------------------------
What is Python keyring lib?
---------------------------

The Python keyring lib provides a easy way to access the system keyring service
from python. It can be used in any application that needs safe password storage.

The keyring library is licensed under both the `MIT license
<http://opensource.org/licenses/MIT>`_ and the PSF license.

These primary keyring services are supported by the Python keyring lib:

* Mac OS X Keychain
* Linux Secret Service
* Windows Credential Vault

Other keyring implementations are provided as well. For more detail, `browse
the source
<https://bitbucket.org/kang/python-keyring-lib/src/default/keyring/backends/>`_.

-------------------------
Installation Instructions
-------------------------

easy_install or pip
===================

Run easy_install or pip::

    $ easy_install keyring
    $ pip install keyring

Source installation
===================

Download the source tarball from https://pypi.python.org/pypi/keyring,
uncompress it, and then run "setup.py install".


-------------
Using Keyring
-------------

The basic usage of keyring is pretty simple: just call `keyring.set_password`
and `keyring.get_password`:

    >>> import keyring
    >>> keyring.set_password("system", "username", "password")
    >>> keyring.get_password("system", "username")
    'password'

--------------------------
Configure your keyring lib
--------------------------

The python keyring lib contains implementations for several backends. The
library will
automatically choose the keyring that is most suitable for your current
environment. You can also specify the keyring you like to be used in the
config file or by calling the ``set_keyring()`` function.

Customize your keyring by config file
=====================================

This section describes how to change your option in the config file.

Config file path
----------------

The configuration of the lib is stored in a file named "keyringrc.cfg". This
file must be found in a platform-specific location. To determine
where the config file is stored, run the following::

    python -c "import keyring.util.platform_; print(keyring.util.platform_.config_root())"

Some keyrings also store the keyring data in the file system. To determine
where the data files are stored, run this command::

    python -c "import keyring.util.platform_; print(keyring.util.platform_.data_root())"


Config file content
-------------------

To specify a keyring backend, set the **default-keyring** option to the
full path of the class for that backend, such as
``keyring.backends.OS_X.Keyring``.

If **keyring-path** is indicated, keyring will add that path to the Python
module search path before loading the backend.

For example, this config might be used to load the SimpleKeyring from the demo
directory in the project checkout::

    [backend]
    default-keyring=simplekeyring.SimpleKeyring
    keyring-path=/home/kang/pyworkspace/python-keyring-lib/demo/


Write your own keyring backend
==============================

The interface for the backend is defined by ``keyring.backend.KeyringBackend``.
Every backend should derive from that base class and define a ``priority``
attribute and three functions: ``get_password()``, ``set_password()``, and
``delete_password()``.

See the ``backend`` module for more detail on the interface of this class.


Set the keyring in runtime
==========================

Keyring additionally allows programmatic configuration of the
backend calling the api ``set_keyring()``. The indicated backend
will subsequently be used to store and retrieve passwords.

Here's an example demonstrating how to invoke ``set_keyring``::

    # define a new keyring class which extends the KeyringBackend
    import keyring.backend

    class TestKeyring(keyring.backend.KeyringBackend):
        """A test keyring which always outputs same password
        """
        priority = 1

        def set_password(self, servicename, username, password):
            pass

        def get_password(self, servicename, username):
            return "password from TestKeyring"

        def delete_password(self, servicename, username, password):
            pass

    # set the keyring for keyring lib
    keyring.set_keyring(TestKeyring())

    # invoke the keyring lib
    try:
        keyring.set_password("demo-service", "tarek", "passexample")
        print("password stored sucessfully")
    except keyring.errors.PasswordSetError:
        print("failed to store password")
    print("password", keyring.get_password("demo-service", "tarek"))


-----------------------------------------------
Integrate the keyring lib with your application
-----------------------------------------------

API interface
=============

The keyring lib has a few functions:

* ``get_keyring()``: Return the currently-loaded keyring implementation.
* ``get_password(service, username)``: Returns the password stored in the
  active keyring. If the password does not exist, it will return None.
* ``set_password(service, username, password)``: Store the password in the
  keyring.
* ``delete_password(service, username)``: Delete the password stored in
  keyring. If the password does not exist, it will raise an exception.

------------
Get involved
------------

Python keyring lib is an open community project and highly welcomes new
contributors.

* Repository: http://bitbucket.org/kang/python-keyring-lib/
* Bug Tracker: http://bitbucket.org/kang/python-keyring-lib/issues/
* Mailing list: http://groups.google.com/group/python-keyring

Running Tests
=============

Tests are `continuously run <https://travis-ci.org/#!/jaraco/keyring>`_ using
Travis-CI.

|BuildStatus|_

.. |BuildStatus| image:: https://secure.travis-ci.org/jaraco/keyring.png
.. _BuildStatus: http://travis-ci.org/jaraco/keyring

To run the tests yourself, you'll want keyring installed to some environment
in which it can be tested. Three recommended techniques are described below.

Using pytest runner
-------------------

Keyring is instrumented with `pytest runner
<https://bitbucket.org/jaraco/pytest-runner>`_. Thus, you may invoke the tests
from any supported Python (with distribute installed) using this command::

    python setup.py ptr

pytest runner will download any unmet dependencies and run the tests using
`pytest <https://bitbucket.org/hpk42/pytest>`_.

This technique is the one used by the Travis-CI script.

Using virtualenv and pytest/nose/unittest2
------------------------------------------

Pytest and Nose are two popular test runners that will discover tests and run
them. Unittest (unittest2 under Python 2.6) also has a mode
to discover tests.

First, however, these test runners typically need a test environment in which
to run. It is recommended that you install keyring to a virtual environment
to avoid interfering with your system environment. For more information, see
the `venv documentation <https://docs.python.org/dev/library/venv.html>`_ or
the `virtualenv homepage <http://www.virtualenv.org>`_.

After you've created (or designated) your environment, install keyring into
the environment by running::

    python setup.py develop

Then, invoke your favorite test runner, e.g.::

    py.test

or::

    nosetests

Using buildout
--------------

Keyring supplies a buildout.cfg for use with buildout. If you have buildout
installed, tests can be invoked as so::

    1. bin/buildout  # prepare the buildout.
    2. bin/test  # execute the test runner.

For more information about the options that the script provides do execute::

    python bin/test --help

-------
Credits
-------

The project was based on Tarek Ziade's idea in `this post`_. Kang Zhang
initially carried it out as a `Google Summer of Code`_ project, and Tarek
mentored Kang on this project.

.. _this post: http://tarekziade.wordpress.com/2009/03/27/pycon-hallway-session-1-a-keyring-library-for-python/
.. _Google Summer of Code: http://socghop.appspot.com/

See CONTRIBUTORS.txt for a complete list of contributors.

