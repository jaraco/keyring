v22.0.0
-------

* Renamed macOS backend from ``OS_X`` to ``macOS``.
  Any users specifying the backend by name will need to
  use the new name ``keyring.backends.macOS``.

v21.8.0
-------

* #438: For better interoperability with other
  applications, ``Windows`` backend now attempts to
  decode passwords using UTF-8 if UTF-16 decoding fails.
  Passwords are still stored as UTF-16.

v21.7.0
-------

* #437: Package now declares typing support.

v21.6.0
-------

* #403: Keyring no longer eagerly initializes the backend
  on import, but instead defers the backend initialization
  until a keyring is accessed. Any callers reliant on this
  early intialization behavior may need to call
  ``keyring.core.init_backend()`` to explicitly initialize
  the detected backend.

v21.5.0
-------

* #474: SecretService and KWallet backends are now
  disabled if the relevant names are not available on
  D-Bus. Keyring should now be much more responsive
  in these environments.

* #463: Fixed regression in KWallet ``get_credential``
  where a simple string was returned instead of a
  SimpleCredential.

v21.4.0
-------

* #431: KWallet backend now supports ``get_credential``.

v21.3.1
-------

* #445: Suppress errors when ``sys.argv`` is not
  a list of at least one element.

v21.3.0
-------

* #440: Keyring now honors XDG_CONFIG_HOME as
  ``~/.config``.
* #452: SecretService ``get_credential`` now returns
  ``None`` for unmatched query.

v21.2.1
-------

* #426: Restored lenience on startup when entry point
  metadata is missing.
* #423: Avoid RecursionError when initializing backends
  when a limit is supplied.

v21.2.0
-------

* #372: Chainer now deterministically resolves at a lower
  priority than the Fail keyring (when there are no backends
  to chain).
* #372: Fail keyring now raises a ``NoKeyringError`` for
  easier selectability.
* #405: Keyring now logs at DEBUG rather than INFO during
  backend startup.

v21.1.1
-------

* Refreshed package metadata.

v21.1.0
-------

* #380: In SecretService backend, close connections after
  using them.

v21.0.0
-------

* Require Python 3.6 or later.

v20.0.1
-------

* #417: Fix TypeError when backend fails to initialize.

v20.0.0
-------

* Extracted ``keyring.testing`` package to contain supporting
  functionality for plugin backends. ``keyring.tests`` has been
  removed from the package.

v19.3.0
-------

* Switch to `importlib.metadata
  <https://docs.python.org/3/library/importlib.metadata.html>`_
  for loading entry points. Removes one dependency on Python 3.8.

* Added new ``KeyringBackend.set_properties_from_env``.

* #382: Add support for alternate persistence scopes for Windows
  backend. Set ``.persist`` to "local machine" or "session"
  to enable the alternate scopes or "enterprise" to use the
  default scope.

* #404: Improve import times when a backend is specifically
  configured by lazily calling ``get_all_keyring``.

19.2.0
------

* Add support for get_credential() with the SecretService backend.

19.1.0
------

* #369: macOS Keyring now honors a ``KEYCHAIN_PATH``
  environment variable. If set, Keyring will use that
  keychain instead of the default.

19.0.2
------

* Refresh package skeleton.
* Adopt `black <https://pypi.org/project/black>`_ code style.

19.0.1
------

* Merge with 18.0.1.

18.0.1
------

* #386: ExceptionInfo no longer retains a reference to the
  traceback.

19.0.0
------

* #383: Drop support for EOL Python 2.7 - 3.4.

18.0.0
------

* #375: On macOS, the backend now raises a ``KeyringLocked``
  when access to the keyring is denied (on get or set) instead
  of ``PasswordSetError`` or ``KeyringError``. Any API users
  may need to account for this change, probably by catching
  the parent ``KeyringError``.
  Additionally, the error message from the underying error is
  now included in any errors that occur.

17.1.1
------

* #368: Update packaging technique to avoid 0.0.0 releases.

17.1.0
------

* #366: When calling ``keyring.core.init_backend``, if any
  limit function is supplied, it is saved and later honored by
  the ``ChainerBackend`` as well.

17.0.0
------

* #345: Remove application attribute from stored passwords
  using SecretService, addressing regression introduced in
  10.5.0 (#292). Impacted Linux keyrings will once again
  prompt for a password for "Python program".

16.1.1
------

* #362: Fix error on import due to circular imports
  on Python 3.4.

16.1.0
------

* Refactor ChainerBackend, introduced in 16.0 to function
  as any other backend, activating when relevant.

16.0.2
------

* #319: In Windows backend, trap all exceptions when
  attempting to import pywin32.

16.0.1
------

* #357: Once again allow all positive, non-zero priority
  keyrings to participate.

16.0.0
------

* #323: Fix race condition in delete_password on Windows.
* #352: All suitable backends (priority 1 and greater) are
  allowed to participate.

15.2.0
------

* #350: Added new API for ``get_credentials``, for backends
  that can resolve both a username and password for a service.

15.1.0
------

* #340: Add the Null keyring, disabled by default.
* #340: Added ``--disable`` option to command-line
  interface.
* #340: Now honor a ``PYTHON_KEYRING_BACKEND``
  environment variable to select a backend. Environments
  may set to ``keyring.backends.null.Keyring`` to disable
  keyring.

15.0.0
------

Removed deprecated ``keyring.util.escape`` module.

Fixed warning about using deprecated Abstract Base Classes
from collections module.

14.0.0
------

Removed ``getpassbackend`` module and alias in
``keyring.get_pass_get_password``. Instead, just use::

    keyring.get_password(getpass.getuser(), 'Python')

13.2.1
------

* #335: Fix regression in command line client.

13.2.0
------

* Keyring command-line interface now reads the password
  directly from stdin if stdin is connected to a pipe.

13.1.0
------

* #329: Improve output of ``keyring --list-backends``.

13.0.0
------

* #327: In kwallet backend, if the collection or item is
  locked, a ``KeyringLocked`` exception is raised. Clients
  expecting a None response from ``get_password`` under
  this condition will need to catch this exception.
  Additionally, an ``InitError`` is now raised if the
  connection cannot be established to the DBus.

* #298: In kwallet backend, when checking an existing
  handle, verify that it is still valid or create a new
  connection.

12.2.1
------

* Fixed issue in SecretService. Ref #226.

12.2.0
------

* #322: Fix AttributeError when ``escape.__builtins__``
  is a dict.

* Deprecated ``keyring.util.escape`` module. If you use
  this module or encounter the warning (on the latest
  release of your packages), please `file a ticket
  <https://github.com/jaraco/keyring/issues/new>`_.

12.1.0
------

* Unpin SecretStorage on Python 3.5+. Requires that
  Setuptools 17.1 be used. Note that the special
  handling will be unnecessary once Pip 9 can be
  assumed (as it will exclude SecretStorage 3 in
  non-viable environments).

12.0.2
------

* Pin SecretStorage to 2.x.

12.0.1
------

* #314: No changes except to rebuild.

12.0.0
------

* #310: Keyring now loads all backends through entry
  points.

For most users, this release will be fully compatible. Some
users may experience compatibility issues if entrypoints is
not installed (as declared) or the metadata on which entrypoints
relies is unavailable. For that reason, the package is released
with a major version bump.

11.1.0
------

* #312: Use ``entrypoints`` instead of pkg_resources to
  avoid performance hit loading pkg_resources. Adds
  a dependency on ``entrypoints``.

11.0.0
------

* #294: No longer expose ``keyring.__version__`` (added
  in 8.1) to avoid performance hit loading pkg_resources.

10.6.0
------

* #299: Keyring exceptions are now derived from a base
  ``keyring.errors.KeyringError``.

10.5.1
------

* #296: Prevent AttributeError on import when Debian has
  created broken dbus installs.

10.5.0
------

* #287: Added ``--list-backends`` option to
  command-line interface.

* Removed ``logger`` from ``keyring``. See #291 for related
  request.

* #292: Set the appid for SecretService & KWallet to
  something meaningful.

10.4.0
------

* #279: In Kwallet, pass mainloop to SessionBus.

* #278: Unpin pywin32-ctypes, but blacklist known
  incompatible versions.

10.3.3
------

* #278: Pin to pywin32-ctypes 0.0.1 to avoid apparent
  breakage introduced in 0.1.0.

10.3.2
------

* #267: More leniently unescape lowercased characters as
  they get re-cased by ConfigParser.

10.3.1
------

* #266: Use private compatibity model rather than six to
  avoid the dependency.

10.3
----

* #264: Implement devpi hook for supplying a password when
  logging in with `devpi <https://pypi.org/project/devpi>`_
  client.

* #260: For macOS, added initial API support for internet
  passwords.

10.2
----

* #259: Allow to set a custom application attribute for
  SecretService backend.

10.1
----

* #253: Backends now expose a '.name' attribute suitable
  for identifying each backend to users.

10.0.2
-----

* #247: Restored console script.

10.0.1
------

* Update readme to reflect test recommendations.

10.0
----

* Drop support for Python 3.2.
* Test suite now uses tox instead of pytest-runner.
  Test requirements are now defined in tests/requirements.txt.

9.3.1
-----

* Link to the new Gitter chat room is now in the
  readme.
* Issue #235: ``kwallet`` backend now returns
  string objects instead of ``dbus.String`` objects,
  for less surprising reprs.
* Minor doc fixes.

9.3
---

* Issue #161: In SecretService backend, unlock
  individual entries.

9.2.1
-----

* Issue #230: Don't rely on dbus-python and instead
  defer to SecretStorage to describe the installation
  requirements.

9.2
---

* Issue #231 via #233: On Linux, ``secretstorage``
  is now a declared dependency, allowing recommended
  keyring to work simply after installation.

9.1
---

* Issue #83 via #229: ``kwallet`` backend now stores
  the service name as a folder name in the backend rather
  than storing all passwords in a Python folder.

9.0
---

* Issue #217: Once again, the OS X backend uses the
  Framework API for invoking the Keychain service.
  As a result, applications utilizing this API will be
  authorized per application, rather than relying on the
  authorization of the 'security' application. Consequently,
  users will be prompted to authorize the system Python
  executable and also new Python executables, such as
  those created by virtualenv.
  #260: No longer does the keyring honor the ``store``
  attribute on the keyring. Only application passwords
  are accessible.

8.7
---

* Changelog now links to issues and provides dates of
  releases.

8.6
---

* Issue #217: Add warning in OS Keyring when 'store'
  is set to 'internet' to determine if this feature is
  used in the wild.

8.5.1
-----

* Pull Request #216: Kwallet backend now has lower
  priority than the preferred SecretService backend,
  now that the desktop check is no longer in place.

8.5
---

* Issue #168: Now prefer KF5 Kwallet to KF4. Users relying
  on KF4 must use prior releases.

8.4
---

* Pull Request #209: Better error message when no backend is
  available (indicating keyrings.alt as a quick workaround).
* Pull Request #208: Fix pywin32-ctypes package name in
  requirements.

8.3
---

* Issue #207: Library now requires win32ctypes on Windows
  systems, which will be installed automatically by
  Setuptools 0.7 or Pip 6 (or later).
* Actually removed QtKwallet, which was meant to be dropped in
  8.0 but somehow remained.

8.2
---

* Update readme to include how-to use with Linux
  non-graphical environments.

8.1
---

* Issue #197: Add ``__version__`` attribute to keyring module.

8.0
---

* Issue #117: Removed all but the preferred keyring backends
  for each of the major desktop platforms:

    - keyring.backends.kwallet.DBusKeyring
    - keyring.backends.OS_X.Keyring
    - keyring.backends.SecretService.Keyring
    - keyring.backends.Windows.WinVaultKeyring

  All other keyrings
  have been moved to a new package, `keyrings.alt
  <https://pypi.python.org/pypi/keyrings.alt>`_ and
  backward-compatibility aliases removed.
  To retain
  availability of these less preferred keyrings, include
  that package in your installation (install both keyring
  and keyrings.alt).

  As these keyrings have moved, any keyrings indicated
  explicitly in configuration will need to be updated to
  replace "keyring.backends." with "keyrings.alt.". For
  example, "keyring.backends.file.PlaintextKeyring"
  becomes "keyrings.alt.file.PlaintextKeyring".

7.3.1
-----

* Issue #194: Redirect away from docs until they have something
  more than the changelog. Users seeking the changelog will
  want to follow the `direct link
  <https://pythonhosted.org/keyring/history.html>`_.

7.3
---

* Issue #117: Added support for filtering which
  backends are acceptable. To limit to only loading recommended
  keyrings (those with priority >= 1), call::

    keyring.core.init_backend(limit=keyring.core.recommended)

7.2
---

* Pull Request #190: OS X backend now exposes a ``keychain``
  attribute, which if set will be used by ``get_password`` when
  retrieving passwords. Useful in environments such as when
  running under cron where the default keychain is not the same
  as the default keychain in a login session. Example usage::

    keyring.get_keyring().keychain = '/path/to/login.keychain'
    pw = keyring.get_password(...)

7.1
---

* Issue #186: Removed preference for keyrings based on
  ``XDG_CURRENT_DESKTOP`` as these values are to varied
  to be a reliable indicator of which keyring implementation
  might be preferable.

7.0.2
-----

* Issue #187: Restore ``Keyring`` name in ``kwallet`` backend.
  Users of keyring 6.1 or later should prefer an explicit reference
  to DBusKeyring or QtKeyring instead.

7.0.1
-----

* Issue #183 and Issue #185: Gnome keyring no longer relies
  on environment variables, but instead relies on the GnomeKeyring
  library to determine viability.

7.0
---

* Issue #99: Keyring now expects the config file to be located
  in the XDG_CONFIG_HOME rather than XDG_DATA_HOME and will
  fail to start if the config is found in the old location but not
  the new. On systems where the two locations are distinct,
  simply copy or symlink the config to remain compatible with
  older versions or move the file to work only with 7.0 and later.

* Replaced Pull Request #182 with a conditional SessionBus
  construction, based on subsequent discussion.

6.1.1
-----

* Pull Request #182: Prevent DBus from indicating as a viable
  backend when no viable X DISPLAY variable is present.

6.1
---

* Pull Request #174: Add DBus backend for KWallet, preferred to Qt
  backend. Theoretically, it should be auto-detected based on
  available libraries and interchangeable with the Qt backend.

6.0
---

* Drop support for Python 2.6.

5.7.1
-----

* Updated project metadata to match Github hosting and
  generally refreshed the metadata structure to match
  practices with other projects.

5.7
---

* Issue #177: Resolve default keyring name on Gnome using the API.
* Issue #145: Add workaround for password exposure through
  process status for most passwords containing simple
  characters.

5.6
---

* Allow keyring to be invoked from command-line with
  ``python -m keyring``.

5.5.1
-----

* Issue #156: Fixed test failures in ``pyfs`` keyring related to
  0.5 release.

5.5
---

* Pull Request #176: Use recommended mechanism for checking
  GnomeKeyring version.

5.4
---

* Prefer setuptools_scm to hgtools.

5.3
---

* Prefer hgtools to setuptools_scm due to `setuptools_scm #21
  <https://bitbucket.org/pypa/setuptools_scm/issue/21>`_.

5.2
---

* Prefer setuptools_scm to hgtools.

5.1
---

* Host project at Github (`repo <https://github.com/jaraco/keyring>`_).

5.0
---

* Version numbering is now derived from the code repository tags via `hgtools
  <https://pypi.python.org/pypi/hgtools>`_.
* Build and install now requires setuptools.

4.1.1
-----

* The entry point group must look like a module name, so the group is now
  "keyring.backends".

4.1
---

* Added preliminary support for loading keyring backends through ``setuptools
  entry points``, specifically "keyring backends".

4.0
---

* Removed ``keyring_path`` parameter from ``load_keyring``. See release notes
  for 3.0.3 for more details.
* Issue #22: Removed support for loading the config from the current
  directory. The config file must now be located in the platform-specific
  config location.

3.8
---

* Issue #22: Deprecated loading of config from current directory. Support for
  loading the config in this manner will be removed in a future version.
* Issue #131: Keyring now will prefer `pywin32-ctypes
  <https://pypi.python.org/pypi/pywin32-ctypes>`_ to pywin32 if available.

3.7
---

* Gnome keyring no longer relies on the GNOME_KEYRING_CONTROL environment
  variable.
* Issue #140: Restore compatibility for older versions of PyWin32.

3.6
---

* `Pull Request #1 (github) <https://github.com/jaraco/keyring/pull/1>`_:
  Add support for packages that wish to bundle keyring by using relative
  imports throughout.

3.5
---

* Issue #49: Give the backend priorities a 1.5 multiplier bump when an
  XDG_CURRENT_DESKTOP environment variable matches the keyring's target
  environment.
* Issue #99: Clarified documentation on location of config and data files.
  Prepared the code base to treat the two differently on Unix-based systems.
  For now, the behavior is unchanged.

3.4
---

* Extracted FileBacked and Encrypted base classes.
* Add a pyinstaller hook to expose backend modules. Ref #124
* Pull request #41: Use errno module instead of hardcoding error codes.
* SecretService backend: correctly handle cases when user dismissed
  the collection creation or unlock prompt.

3.3
---

* Pull request #40: KWallet backend will now honor the ``KDE_FULL_SESSION``
  environment variable as found on openSUSE.

3.2.1
-----

* SecretService backend: use a different function to check that the
  backend is functional. The default collection may not exist, but
  the collection will remain usable in that case.

  Also, make the error message more verbose.

  Resolves https://bugs.launchpad.net/bugs/1242412.

3.2
---

* Issue #120: Invoke KeyringBackend.priority during load_keyring to ensure
  that any keyring loaded is actually viable (or raises an informative
  exception).

* File keyring:

   - Issue #123: fix removing items.
   - Correctly escape item name when removing.
   - Use with statement when working with files.

* Add a test for removing one item in group.

* Issue #81: Added experimental support for third-party backends. See
  `keyring.core._load_library_extensions` for information on supplying
  a third-party backend.

3.1
---

* All code now runs natively on both Python 2 and Python 3, no 2to3 conversion
  is required.
* Testsuite: clean up, and make more use of unittest2 methods.

3.0.5
-----

* Issue #114: Fix logic in pyfs detection.

3.0.4
-----

* Issue #114: Fix detection of pyfs under Mercurial Demand Import.

3.0.3
-----

* Simplified the implementation of ``keyring.core.load_keyring``. It now uses
  ``__import__`` instead of loading modules explicitly. The ``keyring_path``
  parameter to ``load_keyring`` is now deprecated. Callers should instead
  ensure their module is available on ``sys.path`` before calling
  ``load_keyring``. Keyring still honors ``keyring-path``. This change fixes
  Issue #113 in which the explicit module loading of keyring modules was
  breaking package-relative imports.

3.0.2
-----

* Renamed ``keyring.util.platform`` to ``keyring.util.platform_``. As reported
  in Issue #112 and `mercurial_keyring #31
  <https://bitbucket.org/Mekk/mercurial_keyring/issue/31>`_ and in `Mercurial
  itself <http://bz.selenic.com/show_bug.cgi?id=4029>`_, Mercurial's Demand
  Import does not honor ``absolute_import`` directives, so it's not possible
  to have a module with the same name as another top-level module. A patch is
  in place to fix this issue upstream, but to support older Mercurial
  versions, this patch will remain for some time.

3.0.1
-----

* Ensure that modules are actually imported even in Mercurial's Demand Import
  environment.

3.0
---

* Removed support for Python 2.5.
* Removed names in ``keyring.backend`` moved in 1.1 and previously retained
  for compatibility.

2.1.1
-----

* Restored Python 2.5 compatibility (lost in 2.0).

2.1
---

*  Issue #10: Added a 'store' attribute to the OS X Keyring, enabling custom
   instances of the KeyringBackend to use another store, such as the
   'internet' store. For example::

       keys = keyring.backends.OS_X.Keyring()
       keys.store = 'internet'
       keys.set_password(system, user, password)
       keys.get_password(system, user)

   The default for all instances can be set in the class::

       keyring.backends.OS_X.Keyring.store = 'internet'

*  GnomeKeyring: fix availability checks, and make sure the warning
   message from pygobject is not printed.

*  Fixes to GnomeKeyring and SecretService tests.

2.0.3
-----

*  Issue #112: Backend viability/priority checks now are more aggressive about
   module presence checking, requesting ``__name__`` from imported modules to
   force the demand importer to actually attempt the import.

2.0.2
-----

*  Issue #111: Windows backend isn't viable on non-Windows platforms.

2.0.1
-----

*  Issue #110: Fix issues with ``Windows.RegistryKeyring``.

2.0
---

*  Issue #80: Prioritized backend support. The primary interface for Keyring
   backend classes has been refactored to now emit a 'priority' based on the
   current environment (operating system, libraries available, etc). These
   priorities provide an indication of the applicability of that backend for
   the current environment. Users are still welcome to specify a particular
   backend in configuration, but the default behavior should now be to select
   the most appropriate backend by default.

1.6.1
-----

* Only include pytest-runner in 'setup requirements' when ptr invocation is
  indicated in the command-line (Issue #105).

1.6
---

*  GNOME Keyring backend:

   - Use the same attributes (``username`` / ``service``) as the SecretService
     backend uses, allow searching for old ones for compatibility.
   - Also set ``application`` attribute.
   - Correctly handle all types of errors, not only ``CANCELLED`` and ``NO_MATCH``.
   - Avoid printing warnings to stderr when GnomeKeyring is not available.

* Secret Service backend:

   - Use a better label for passwords, the same as GNOME Keyring backend uses.

1.5
---

*  SecretService: allow deleting items created using previous python-keyring
   versions.

   Before the switch to secretstorage, python-keyring didn't set "application"
   attribute. Now in addition to supporting searching for items without that
   attribute, python-keyring also supports deleting them.

*  Use ``secretstorage.get_default_collection`` if it's available.

   On secretstorage 1.0 or later, python-keyring now tries to create the
   default collection if it doesn't exist, instead of just raising the error.

*  Improvements for tests, including fix for Issue #102.

1.4
---

* Switch GnomeKeyring backend to use native libgnome-keyring via
  GObject Introspection, not the obsolete python-gnomekeyring module.

1.3
---

* Use the `SecretStorage library <https://pypi.python.org/pypi/SecretStorage>`_
  to implement the Secret Service backend (instead of using dbus directly).
  Now the keyring supports prompting for and deleting passwords. Fixes #69,
  #77, and #93.
* Catch `gnomekeyring.IOError` per the issue `reported in Nova client
  <https://bugs.launchpad.net/python-novaclient/+bug/1116302>`_.
* Issue #92 Added support for delete_password on Mac OS X Keychain.

1.2.3
-----

* Fix for Encrypted File backend on Python 3.
* Issue #97 Improved support for PyPy.

1.2.2
-----

* Fixed handling situations when user cancels kwallet dialog or denies access
  for the app.

1.2.1
-----

* Fix for kwallet delete.
* Fix for OS X backend on Python 3.
* Issue #84: Fix for Google backend on Python 3 (use of raw_input not caught
  by 2to3).

1.2
---

* Implemented delete_password on most keyrings. Keyring 2.0 will require
  delete_password to implement a Keyring. Fixes #79.

1.1.2
-----

* Issue #78: pyfilesystem backend now works on Windows.

1.1.1
-----

* Fixed MANIFEST.in so .rst files are included.

1.1
---

This is the last build that will support installation in a pure-distutils
mode. Subsequent releases will require setuptools/distribute to install.
Python 3 installs have always had this requirement (for 2to3 install support),
but starting with the next minor release (1.2+), setuptools will be required.

Additionally, this release has made some substantial refactoring in an
attempt to modularize the backends. An attempt has been made to maintain 100%
backward-compatibility, although if your library does anything fancy with
module structure or clasess, some tweaking may be necessary. The
backward-compatible references will be removed in 2.0, so the 1.1+ releases
represent a transitional implementation which should work with both legacy
and updated module structure.

* Added a console-script 'keyring' invoking the command-line interface.
* Deprecated _ExtensionKeyring.
* Moved PasswordSetError and InitError to an `errors` module (references kept
  for backward-compatibility).
* Moved concrete backend implementations into their own modules (references
  kept for backward compatibility):

  - OSXKeychain -> backends.OS_X.Keyring
  - GnomeKeyring -> backends.Gnome.Keyring
  - SecretServiceKeyring -> backends.SecretService.Keyring
  - KDEKWallet -> backends.kwallet.Keyring
  - BasicFileKeyring -> backends.file.BaseKeyring
  - CryptedFileKeyring -> backends.file.EncryptedKeyring
  - UncryptedFileKeyring -> backends.file.PlaintextKeyring
  - Win32CryptoKeyring -> backends.Windows.EncryptedKeyring
  - WinVaultKeyring -> backends.Windows.WinVaultKeyring
  - Win32CryptoRegistry -> backends.Windows.RegistryKeyring
  - select_windows_backend -> backends.Windows.select_windows_backend
  - GoogleDocsKeyring -> backends.Google.DocsKeyring
  - Credential -> keyring.credentials.Credential
  - BaseCredential -> keyring.credentials.SimpleCredential
  - EnvironCredential -> keyring.credentials.EnvironCredential
  - GoogleEnvironCredential -> backends.Google.EnvironCredential
  - BaseKeyczarCrypter -> backends.keyczar.BaseCrypter
  - KeyczarCrypter -> backends.keyczar.Crypter
  - EnvironKeyczarCrypter -> backends.keyczar.EnvironCrypter
  - EnvironGoogleDocsKeyring -> backends.Google.KeyczarDocsKeyring
  - BasicPyfilesystemKeyring -> backends.pyfs.BasicKeyring
  - UnencryptedPyfilesystemKeyring -> backends.pyfs.PlaintextKeyring
  - EncryptedPyfilesystemKeyring -> backends.pyfs.EncryptedKeyring
  - EnvironEncryptedPyfilesystemKeyring -> backends.pyfs.KeyczarKeyring
  - MultipartKeyringWrapper -> backends.multi.MultipartKeyringWrapper

* Officially require Python 2.5 or greater (although unofficially, this
  requirement has been in place since 0.10).

1.0
---

This backward-incompatible release attempts to remove some cruft from the
codebase that's accumulated over the versions.

* Removed legacy file relocation support. `keyring` no longer supports loading
  configuration or file-based backends from ~. If upgrading from 0.8 or later,
  the files should already have been migrated to their new proper locations.
  If upgrading from 0.7.x or earlier, the files will have to be migrated
  manually.
* Removed CryptedFileKeyring migration support. To maintain an existing
  CryptedFileKeyring, one must first upgrade to 0.9.2 or later and access the
  keyring before upgrading to 1.0 to retain the existing keyring.
* File System backends now create files without group and world permissions.
  Fixes #67.

0.10.1
------

* Merged 0.9.3 to include fix for #75.

0.10
----

* Add support for using `Keyczar <http://www.keyczar.org/>`_ to encrypt
  keyrings. Keyczar is "an open source cryptographic toolkit designed to make
  it easier and safer for developers to use cryptography in their
  applications."
* Added support for storing keyrings on Google Docs or any other filesystem
  supported by pyfilesystem.
* Fixed issue in Gnome Keyring when unicode is passed as the service name,
  username, or password.
* Tweaked SecretService code to pass unicode to DBus, as unicode is the
  preferred format.
* Issue #71 - Fixed logic in CryptedFileKeyring.
* Unencrypted keyring file will be saved with user read/write (and not group
  or world read/write).

0.9.3
-----

* Ensure migration is run when get_password is called. Fixes #75. Thanks to
  Marc Deslauriers for reporting the bug and supplying the patch.

0.9.2
-----

* Keyring 0.9.1 introduced a whole different storage format for the
  CryptedFileKeyring, but this introduced some potential compatibility issues.
  This release incorporates the security updates but reverts to the INI file
  format for storage, only encrypting the passwords and leaving the service
  and usernames in plaintext. Subsequent releases may incorporate a new
  keyring to implement a whole-file encrypted version. Fixes #64.
* The CryptedFileKeyring now requires simplejson for Python 2.5 clients.

0.9.1
-----

* Fix for issue where SecretServiceBackend.set_password would raise a
  UnicodeError on Python 3 or when a unicode password was provided on Python
  2.
* CryptedFileKeyring now uses PBKDF2 to derive the key from the user's
  password and a random hash. The IV is chosen randomly as well. All the
  stored passwords are encrypted at once. Any keyrings using the old format
  will be automatically converted to the new format (but will no longer be
  compatible with 0.9 and earlier). The user's password is no longer limited
  to 32 characters. PyCrypto 2.5 or greater is now required for this keyring.

0.9
---

* Add support for GTK 3 and secret service D-Bus. Fixes #52.
* Issue #60 - Use correct method for decoding.

0.8.1
-----

* Fix regression in keyring lib on Windows XP where the LOCALAPPDATA
  environment variable is not present.

0.8
---

* Mac OS X keyring backend now uses subprocess calls to the `security`
  command instead of calling the API, which with the latest updates, no
  longer allows Python to invoke from a virtualenv. Fixes issue #13.
* When using file-based storage, the keyring files are no longer stored
  in the user's home directory, but are instead stored in platform-friendly
  locations (`%localappdata%\Python Keyring` on Windows and according to
  the freedesktop.org Base Dir Specification
  (`$XDG_DATA_HOME/python_keyring` or `$HOME/.local/share/python_keyring`)
  on other operating systems). This fixes #21.

*Backward Compatibility Notice*

Due to the new storage location for file-based keyrings, keyring 0.8
supports backward compatibility by automatically moving the password
files to the updated location. In general, users can upgrade to 0.8 and
continue to operate normally. Any applications that customize the storage
location or make assumptions about the storage location will need to take
this change into consideration. Additionally, after upgrading to 0.8,
it is not possible to downgrade to 0.7 without manually moving
configuration files. In 1.0, the backward compatibility
will be removed.

0.7.1
-----

* Removed non-ASCII characters from README and CHANGES docs (required by
  distutils if we're to include them in the long_description). Fixes #55.

0.7
---

* Python 3 is now supported. All tests now pass under Python 3.2 on
  Windows and Linux (although Linux backend support is limited). Fixes #28.
* Extension modules on Mac and Windows replaced by pure-Python ctypes
  implementations. Thanks to Jerome Laheurte.
* WinVaultKeyring now supports multiple passwords for the same service. Fixes
  #47.
* Most of the tests don't require user interaction anymore.
* Entries stored in Gnome Keyring appears now with a meaningful name if you try
  to browser your keyring (for ex. with Seahorse)
* Tests from Gnome Keyring no longer pollute the user own keyring.
* `keyring.util.escape` now accepts only unicode strings. Don't try to encode
  strings passed to it.

0.6.2
-----

* fix compiling on OSX with XCode 4.0

0.6.1
-----

* Gnome keyring should not be used if there is no DISPLAY or if the dbus is
  not around (https://bugs.launchpad.net/launchpadlib/+bug/752282).

* Added `keyring.http` for facilitating HTTP Auth using keyring.

* Add a utility to access the keyring from the command line.

0.5.1
-----

* Remove a spurious KDE debug message when using KWallet

* Fix a bug that caused an exception if the user canceled the KWallet dialog
  (https://bitbucket.org/kang/python-keyring-lib/issue/37/user-canceling-of-kde-wallet-dialogs).

0.5
---

* Now using the existing Gnome and KDE python libs instead of custom C++
  code.

* Using the getpass module instead of custom code

0.4
---

* Fixed the setup script (some subdirs were not included in the release.)

0.3
---

* Fixed keyring.core when the user doesn't have a cfg, or is not
  properly configured.

* Fixed escaping issues for usernames with non-ascii characters

0.2
---

* Add support for Python 2.4+
  http://bitbucket.org/kang/python-keyring-lib/issue/2

* Fix the bug in KDE Kwallet extension compiling
  http://bitbucket.org/kang/python-keyring-lib/issue/3
