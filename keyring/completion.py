import argparse

try:
    import shtab
except ImportError:
    pass


# it completes keyring backends for `keyring -b` by the output
# of `keyring --list-backends`
# % keyring -b <TAB>
# keyring priority
# keyring.backends.chainer.ChainerBackend   10
# keyring.backends.fail.Keyring             0
# ...                                       ...
PREAMBLE = {
    "zsh": r"""
backend_complete() {
  local line
  while read -r line; do
    choices+=(${${line/ \(priority: /\\\\:}/)/})
  done <<< "$($words[1] --list-backends)"
  _arguments "*:keyring priority:(($choices))"
}
"""
}
BACKEND_COMPLETE = {"zsh": "backend_complete"}


class _MissingCompletionAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string):
        print("Install keyring[completion] for completion support.")
        parser.exit(0)


def add_completion_notice(parser):
    """Add completion argument to parser."""
    parser.add_argument(
        "--print-completion",
        choices=["bash", "zsh", "tcsh"],
        action=_MissingCompletionAction,
        help="print shell completion script",
    )
    return parser


def get_action(parser, option):
    (match,) = (action for action in parser._actions if option in action.option_strings)
    return match


def install(parser):
    try:
        install_completion(parser)
    except NameError:
        add_completion_notice(parser)


def install_completion(parser):
    shtab.add_argument_to(parser, preamble=PREAMBLE)
    get_action(parser, '--keyring-path').completion = shtab.DIR
    get_action(parser, '--keyring-backend').completion = BACKEND_COMPLETE
    return parser
