import getpass
import itertools
import sys
from unittest import mock

import pytest

from keyring import cli

flatten = itertools.chain.from_iterable


class PasswordEmitter:
    """
    Replacement for getpass() to emit passwords:

    >>> pe = PasswordEmitter('foo', 'bar')
    >>> pe()
    'foo'
    >>> pe()
    'bar'
    >>> pe()
    'foo'
    """

    def __init__(self, *passwords):
        self.passwords = flatten(itertools.repeat(passwords))

    def __call__(self, unused_prompt=None):
        return next(self.passwords)


@pytest.fixture
def mocked_set():
    with mock.patch('keyring.cli.set_password') as set_password:
        yield set_password


def test_set_interactive(monkeypatch, mocked_set):
    tool = cli.CommandLineTool()
    tool.service = 'svc'
    tool.username = 'usr'
    monkeypatch.setattr(sys.stdin, 'isatty', lambda: True)
    monkeypatch.setattr(getpass, 'getpass', PasswordEmitter('foo123'))
    tool.do_set()
    mocked_set.assert_called_once_with('svc', 'usr', 'foo123')


def test_set_pipe(monkeypatch, mocked_set):
    tool = cli.CommandLineTool()
    tool.service = 'svc'
    tool.username = 'usr'
    monkeypatch.setattr(sys.stdin, 'isatty', lambda: False)
    monkeypatch.setattr(sys.stdin, 'read', lambda: 'foo123')
    tool.do_set()
    mocked_set.assert_called_once_with('svc', 'usr', 'foo123')


def test_set_pipe_newline(monkeypatch, mocked_set):
    tool = cli.CommandLineTool()
    tool.service = 'svc'
    tool.username = 'usr'
    monkeypatch.setattr(sys.stdin, 'isatty', lambda: False)
    monkeypatch.setattr(sys.stdin, 'read', lambda: 'foo123\n')
    tool.do_set()
    mocked_set.assert_called_once_with('svc', 'usr', 'foo123')
