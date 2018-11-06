import platform

collect_ignore = [
    "hook-keyring.backend.py",
]

if platform.system() != 'Darwin':
    collect_ignore.append('keyring/backends/_OS_X_API.py')

collect_ignore.append('keyring/devpi_client.py')


def pytest_configure():
        workaround_sugar_issue_159()


def workaround_sugar_issue_159():
    "https://github.com/Frozenball/pytest-sugar/159"
    import pytest_sugar
    pytest_sugar.SugarTerminalReporter.pytest_runtest_logfinish = \
        lambda self: None
