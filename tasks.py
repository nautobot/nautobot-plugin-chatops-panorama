"""Tasks for use with Invoke.

(c) 2020-2021 Network To Code
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
  http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from distutils.util import strtobool
from invoke import Collection, task as invoke_task, UnexpectedExit
import json
import os
import time

ENV_FILES_DIR = os.path.join(os.path.dirname(__file__), "development/")
CREDS_ENV_FILE = os.path.join(ENV_FILES_DIR, "creds.env")
MATTERMOST_ENV_FILE = os.path.join(ENV_FILES_DIR, "mattermost.env")


def is_truthy(arg):
    """Convert "truthy" strings into Booleans.

    Examples:
        >>> is_truthy('yes')
        True
    Args:
        arg (str): Truthy string (True values are y, yes, t, true, on and 1; false values are n, no,
        f, false, off and 0. Raises ValueError if val is anything else.
    """
    if isinstance(arg, bool):
        return arg
    return bool(strtobool(arg))


# Use pyinvoke configuration for default values, see http://docs.pyinvoke.org/en/stable/concepts/configuration.html
# Variables may be overwritten in invoke.yml or by the environment variables INVOKE_NAUTOBOT_PLUGIN_CHATOPS_PANORAMA_xxx
compose_files = ["docker-compose.requirements.yml", "docker-compose.base.yml", "docker-compose.dev.yml"]
compose_files.append("docker-compose.mattermost-dev.yml")

namespace = Collection("nautobot_plugin_chatops_panorama")
namespace.configure(
    {
        "nautobot_plugin_chatops_panorama": {
            "nautobot_ver": "latest",
            "project_name": "nautobot_plugin_chatops_panorama",
            "python_ver": "3.7",
            "local": False,
            "compose_dir": os.path.join(os.path.dirname(__file__), "development"),
            "compose_files": compose_files,
        }
    }
)


def task(function=None, *args, **kwargs):
    """Task decorator to override the default Invoke task decorator and add each task to the invoke namespace."""

    def task_wrapper(function=None):
        """Wrapper around invoke.task to add the task to the namespace as well."""
        if args or kwargs:
            task_func = invoke_task(*args, **kwargs)(function)
        else:
            task_func = invoke_task(function)
        namespace.add_task(task_func)
        return task_func

    if function:
        # The decorator was called with no arguments
        return task_wrapper(function)
    # The decorator was called with arguments
    return task_wrapper


def docker_compose(context, command, **kwargs):
    """Helper function for running a specific docker-compose command with all appropriate parameters and environment.

    Args:
        context (obj): Used to run specific commands
        command (str): Command string to append to the "docker-compose ..." command, such as "build", "up", etc.
        **kwargs: Passed through to the context.run() call.
    """
    build_env = {
        "NAUTOBOT_VER": context.nautobot_plugin_chatops_panorama.nautobot_ver,
        "PYTHON_VER": context.nautobot_plugin_chatops_panorama.python_ver,
    }
    compose_command = f'docker-compose --project-name {context.nautobot_plugin_chatops_panorama.project_name} --project-directory "{context.nautobot_plugin_chatops_panorama.compose_dir}"'
    for compose_file in context.nautobot_plugin_chatops_panorama.compose_files:
        compose_file_path = os.path.join(context.nautobot_plugin_chatops_panorama.compose_dir, compose_file)
        compose_command += f' -f "{compose_file_path}"'
    compose_command += f" {command}"
    print(f'Running docker-compose command "{command}"')
    return context.run(compose_command, env=build_env, **kwargs)


def run_command(context, command, **kwargs):
    """Wrapper to run a command locally or inside the nautobot container."""
    if is_truthy(context.nautobot_plugin_chatops_panorama.local):
        context.run(command, **kwargs)
    else:
        # Check if netbox is running, no need to start another netbox container to run a command
        docker_compose_status = "ps --services --filter status=running"
        results = docker_compose(context, docker_compose_status, hide="out")
        if "nautobot" in results.stdout:
            compose_command = f"exec nautobot {command}"
        else:
            compose_command = f"run --entrypoint '{command}' nautobot"

        docker_compose(context, compose_command, pty=True)


def load_env_dotf(dotf_path):
    """Build dict with ENV vars loaded from .env file.

    Args:
        dotf_path (Path): Path to the .env file
    Returns:
        dict: ENV vars loaded from .env file.
    """
    env_vars = {}
    with open(dotf_path, mode="r", encoding="utf-8") as envf:
        for line in envf.read().splitlines():
            if "=" in line:
                env_key, env_val = line.split("=", maxsplit=1)
                env_vars[env_key] = env_val

    return env_vars


# ------------------------------------------------------------------------------
# BUILD
# ------------------------------------------------------------------------------
@task(
    help={
        "force_rm": "Always remove intermediate containers",
        "cache": "Whether to use Docker's cache when building the image (defaults to enabled)",
    }
)
def build(context, force_rm=False, cache=True):
    """Build Nautobot docker image."""
    command = "build"
    if not cache:
        command += " --no-cache"
    if force_rm:
        command += " --force-rm"

    print(f"Building Nautobot with Python {context.nautobot_plugin_chatops_panorama.python_ver}...")
    docker_compose(context, command)


@task
def generate_packages(context):
    """Generate all Python packages inside docker and copy the file locally under dist/."""
    command = "poetry build"
    run_command(context, command)


# ------------------------------------------------------------------------------
# START / STOP / DEBUG
# ------------------------------------------------------------------------------
@task
def debug(context):
    """Start Nautobot and its dependencies in debug mode."""
    print("Starting Nautobot in debug mode...")
    docker_compose(context, "up")


@task
def start(context):
    """Start Nautobot and its dependencies in detached mode."""
    print("Starting Nautobot in detached mode...")
    docker_compose(context, "up --detach")


@task
def restart(context):
    """Gracefully restart all containers."""
    print("Restarting Nautobot...")
    docker_compose(context, "restart")


@task
def stop(context):
    """Stop Nautobot and its dependencies."""
    print("Stopping Nautobot...")
    docker_compose(context, "down")


@task
def destroy(context):
    """Destroy all containers and volumes."""
    print("Destroying Nautobot...")
    docker_compose(context, "down --volumes")


@task
def vscode(context):
    """Launch Visual Studio Code with the appropriate Environment variables to run in a container."""
    command = "code nautobot.code-workspace"

    context.run(command)


# ------------------------------------------------------------------------------
# ACTIONS
# ------------------------------------------------------------------------------
@task
def nbshell(context):
    """Launch an interactive nbshell session."""
    command = "nautobot-server nbshell"
    run_command(context, command)


@task
def cli(context):
    """Launch a bash shell inside the running Nautobot container."""
    run_command(context, "bash")


@task(
    help={
        "user": "name of the superuser to create (default: admin)",
    }
)
def createsuperuser(context, user="admin"):
    """Create a new Nautobot superuser account (default: "admin"), will prompt for password."""
    command = f"nautobot-server createsuperuser --username {user}"

    run_command(context, command)


@task(
    help={
        "name": "name of the migration to be created; if unspecified, will autogenerate a name",
    }
)
def makemigrations(context, name=""):
    """Perform makemigrations operation in Django."""
    command = "nautobot-server makemigrations nautobot_plugin_chatops_panorama"

    if name:
        command += f" --name {name}"

    run_command(context, command)


@task
def migrate(context):
    """Perform migrate operation in Django."""
    command = "nautobot-server migrate"

    run_command(context, command)


@task(help={})
def post_upgrade(context):
    """
    Performs Nautobot common post-upgrade operations using a single entrypoint.

    This will run the following management commands with default settings, in order:

    - migrate
    - trace_paths
    - collectstatic
    - remove_stale_contenttypes
    - clearsessions
    - invalidate all
    """
    command = "nautobot-server post_upgrade"

    run_command(context, command)


@task
def setup_mattermost(context):
    """Setup local Mattermost dev instance for testing ChatOps against."""
    env = load_env_dotf(CREDS_ENV_FILE)
    env.update(load_env_dotf(MATTERMOST_ENV_FILE))

    docker_compose(context, "up -d mattermost")
    print("Waiting for Mattermost server...")

    attempts = 1
    print(f"Waiting for server, attempt no: {attempts} ...")
    while attempts < 30:
        cmd_result = docker_compose(
            context,
            f"exec mattermost mmctl auth login {env['MM_SERVICESETTINGS_SITEURL']} --name local-server"
            f" --username {env['MM_ADMIN_USERNAME']} --password {env['MM_ADMIN_PASSWORD']}",
            pty=True,
            hide=True,
        )
        if "connection refused" in cmd_result.stdout:
            attempts += 1
            print(f"Waiting for server, attempt no {attempts} ...")
            time.sleep(2)
        else:
            break

    cmd_result = docker_compose(context, "exec mattermost mmctl command list --format json", pty=True, hide=True)

    existing_commands = (
        [] if "null" in cmd_result.stdout else [command["trigger"] for command in json.loads(cmd_result.stdout)]
    )

    chatbot_commands = [cmd.strip() for cmd in env.get("CHATBOT_COMMANDS", "nautobot").split(",")]

    for mm_command in chatbot_commands:
        if mm_command in existing_commands:
            continue
        cmd_result = docker_compose(
            context,
            f"exec mattermost mmctl command create automationteam --creator {env['MM_ADMIN_USERNAME']} --title Nautobot"
            f" --trigger-word {mm_command} --url http://nautobot:8080/api/plugins/chatops/mattermost/slash_command/"
            " --post --autocomplete --format json",
            pty=True,
        )
        command_result = json.loads(cmd_result.stdout)
        cmd_token_file = os.path.join(ENV_FILES_DIR, f"{mm_command}_cmd_token.txt")
        with open(cmd_token_file, mode="w", encoding="utf-8") as file_out:
            file_out.write(command_result["token"])

        try:
            cmd_result = docker_compose(
                context,
                f"exec mattermost mmctl token list {env['MM_BOT_USERNAME']}",
                pty=True,
            )
        # If no tokens are present exit code is set to 1 and exception is raised
        except UnexpectedExit:
            # Generate bot token and related DB records
            docker_compose(
                context,
                f"exec mattermost mmctl token generate {env['MM_BOT_USERNAME']} Nautobot --format json",
                pty=True,
            )
            # Replace bot token with a static pre-defined value
            docker_compose(
                context,
                f"exec mattermost mysql --user=\"{env['MM_USERNAME']}\" --password=\"{env['MM_PASSWORD']}\" --database=\"{env['MM_DBNAME']}\""  # nosec - ignore Bandit error "B608:hardcoded_sql_expressions" as this is only a local dev/test instance
                f" --execute=\"UPDATE UserAccessTokens SET Token = '{env['MATTERMOST_API_TOKEN']}' WHERE UserId = (SELECT Id FROM Users WHERE Username = '{env['MM_BOT_USERNAME']}');\"",
                pty=True,
            )

    print("Waiting for Nautobot server...")
    time.sleep(15)
    docker_compose(
        context,
        "run nautobot sh /source/development/configure_chatops.sh",
        pty=True,
    )


# ------------------------------------------------------------------------------
# TESTS
# ------------------------------------------------------------------------------
@task(
    help={
        "autoformat": "Apply formatting recommendations automatically, rather than failing if formatting is incorrect.",
    }
)
def black(context, autoformat=False):
    """Check Python code style with Black."""
    if autoformat:
        black_command = "black"
    else:
        black_command = "black --check --diff"

    command = f"{black_command} ."

    run_command(context, command)


@task
def flake8(context):
    """Check for PEP8 compliance and other style issues."""
    command = "flake8 ."
    run_command(context, command)


@task
def hadolint(context):
    """Check Dockerfile for hadolint compliance and other style issues."""
    command = "hadolint development/Dockerfile"
    run_command(context, command)


@task
def pylint(context):
    """Run pylint code analysis."""
    command = 'pylint --init-hook "import nautobot; nautobot.setup()" --rcfile pyproject.toml nautobot_plugin_chatops_panorama'
    run_command(context, command)


@task
def yamllint(context):
    """Run yamllint to validate formating adheres to NTC defined YAML standards.

    Args:
        context (obj): Used to run specific commands
    """
    command = "yamllint . --format standard"
    run_command(context, command)


@task
def pydocstyle(context):
    """Run pydocstyle to validate docstring formatting adheres to NTC defined standards."""
    # We exclude the /migrations/ directory since it is autogenerated code
    command = "pydocstyle ."
    run_command(context, command)


@task
def bandit(context):
    """Run bandit to validate basic static code security analysis."""
    command = "bandit --recursive . --configfile .bandit.yml"
    run_command(context, command)


@task
def check_migrations(context):
    """Check for missing migrations."""
    command = "nautobot-server --config=nautobot/core/tests/nautobot_config.py makemigrations --dry-run --check"

    run_command(context, command)


@task(
    help={
        "keepdb": "save and re-use test database between test runs for faster re-testing.",
        "label": "specify a directory or module to test instead of running all Nautobot tests",
        "failfast": "fail as soon as a single test fails don't run the entire test suite",
        "buffer": "Discard output from passing tests",
    }
)
def unittest(context, keepdb=False, label="nautobot_plugin_chatops_panorama", failfast=False, buffer=True):
    """Run Nautobot unit tests."""
    command = f"coverage run --module nautobot.core.cli test {label}"

    if keepdb:
        command += " --keepdb"
    if failfast:
        command += " --failfast"
    if buffer:
        command += " --buffer"
    run_command(context, command)


@task
def unittest_coverage(context):
    """Report on code test coverage as measured by 'invoke unittest'."""
    command = "coverage report --skip-covered --include 'nautobot_plugin_chatops_panorama/*' --omit *migrations*"

    run_command(context, command)


@task(
    help={
        "failfast": "fail as soon as a single test fails don't run the entire test suite",
    }
)
def tests(context, failfast=False):
    """Run all tests for this plugin."""
    # If we are not running locally, start the docker containers so we don't have to for each test
    if not is_truthy(context.nautobot_plugin_chatops_panorama.local):
        print("Starting Docker Containers...")
        start(context)
    # Sorted loosely from fastest to slowest
    print("Running black...")
    black(context)
    print("Running flake8...")
    flake8(context)
    print("Running yamllint...")
    yamllint(context)
    print("Running bandit...")
    bandit(context)
    print("Running pydocstyle...")
    pydocstyle(context)
    print("Running pylint...")
    pylint(context)
    print("Running unit tests...")
    unittest(context, failfast=failfast)
    print("All tests have passed!")
    unittest_coverage(context)
