from argparse import Action

FILE = None
DIRECTORY = DIR = None


class _PrintCompletionAction(Action):
    """Print completion action."""

    def __call__(self, parser, namespace, values, option_string):
        print("Please install shtab firstly!")
        parser.exit(0)


def add_argument_to(parser, *args, **kwargs):
    """Add completion argument to parser."""
    Action.complete = None  # type: ignore
    parser.add_argument(
        "--print-completion",
        choices=["bash", "zsh", "tcsh"],
        action=_PrintCompletionAction,
        help="print shell completion script",
    )
    return parser
