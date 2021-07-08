"""Example rq worker to handle /panorama chat commands with 1 subcommand addition."""
from django_rq import job

from nautobot_chatops.choices import CommandStatusChoices
from nautobot_chatops.workers import handle_subcommands, subcommand_of
from nautobot_chatops.workers.helper_functions import nautobot_logo


@job("default")
def panorama(subcommand, **kwargs):
    """Perform panorama and its subcommands."""
    return handle_subcommands("panorama", subcommand, **kwargs)


@subcommand_of("panorama")
def addition(dispatcher, first_arg, second_arg):
    """Example Addition of 2 arguments."""
    dispatcher.send_blocks(
        dispatcher.command_response_header(
            "panorama",
            "addition",
            [("First Parameter", first_arg), ("Second Parameter", second_arg)],
            f"The result of {first_arg}+{second_arg} is {first_arg+second_arg}",
            nautobot_logo(dispatcher),
        )
    )
    return CommandStatusChoices.STATUS_SUCCEEDED