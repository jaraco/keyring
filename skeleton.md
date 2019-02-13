# Overview

This project is merged with [skeleton](https://github.com/jaraco/skeleton). What is skeleton? It's the scaffolding of a Python project jaraco [introduced in his blog](https://blog.jaraco.com/a-project-skeleton-for-python-projects/). It seeks to provide a means to re-use techniques and inherit advances when managing projects for distribution.

## An SCM Managed Approach

While maintaining dozens of projects in PyPI, jaraco derives best practices for project distribution and publishes them in the [skeleton repo](https://github.com/jaraco/skeleton), a git repo capturing the evolution and culmination of these best practices.

It's intended to be used by a new or existing project to adopt these practices and honed and proven techniques. Adopters are encouraged to use the project directly and maintain a small deviation from the technique, make their own fork for more substantial changes unique to their environment or preferences, or simply adopt the skeleton once and abandon it thereafter.

The primary advantage to using an SCM for maintaining these techniques is that those tools help facilitate the merge between the template and its adopting projects.

Another advantage to using an SCM-managed approach is that tools like GitHub recognize that a change in the skeleton is the _same change_ across all projects that merge with that skeleton. Without the ancestry, with a traditional copy/paste approach, a [commit like this](https://github.com/jaraco/skeleton/commit/12eed1326e1bc26ce256e7b3f8cd8d3a5beab2d5) would produce notifications in the upstream project issue for each and every application, but because it's centralized, GitHub provides just the one notification when the change is added to the skeleton.

# Usage

## new projects

To use skeleton for a new project, simply pull the skeleton into a new project:

```
$ git init my-new-project
$ cd my-new-project
$ git pull gh://jaraco/skeleton
```

Now customize the project to suit your individual project needs.

## existing projects

If you have an existing project, you can still incorporate the skeleton by merging it into the codebase.

```
$ git merge skeleton --allow-unrelated-histories
```

The `--allow-unrelated-histories` is necessary because the history from the skeleton was previously unrelated to the existing codebase. Resolve any merge conflicts and commit to the master, and now the project is based on the shared skeleton.

## Updating

Whenever a change is needed or desired for the general technique for packaging, it can be made in the skeleton project and then merged into each of the derived projects as needed, recommended before each release. As a result, features and best practices for packaging are centrally maintained and readily trickle into a whole suite of packages. This technique lowers the amount of tedious work necessary to create or maintain a project, and coupled with other techniques like continuous integration and deployment, lowers the cost of creating and maintaining refined Python projects to just a few, familiar git operations.

Thereafter, the target project can make whatever customizations it deems relevant to the scaffolding. The project may even at some point decide that the divergence is too great to merit renewed merging with the original skeleton. This approach applies maximal guidance while creating minimal constraints.

# Features

The features/techniques employed by the skeleton include:

- PEP 517/518 based build relying on setuptools as the build tool
- setuptools declarative configuration using setup.cfg
- tox for running tests
- A README.rst as reStructuredText with some popular badges, but with readthedocs and appveyor badges commented out
- A CHANGES.rst file intended for publishing release notes about the project.

## Packaging Conventions

A pyproject.toml is included to enable PEP 517 and PEP 518 compatibility and declares the requirements necessary to build the project on setuptools (a minimum version compatible with setup.cfg declarative config).

The setup.cfg file implements the following features:

- Assumes universal wheel for release
- Advertises the project's LICENSE file (MIT by default)
- Reads the README.rst file into the long description
- Some common Trove classifiers
- Includes all packages discovered in the repo
- Data files in the package are also included (not just Python files)
- Declares the required Python versions
- Declares install requirements (empty by default)
- Declares setup requirements for legacy environments
- Supplies two 'extras':
  - testing: requirements for running tests
  - docs: requirements for building docs
  - these extras split the declaration into "upstream" (requirements as declared by the skeleton) and "local" (those specific to the local project); these markers help avoid merge conflicts
- Placeholder for defining entry points

Additionally, the setup.py file declares `use_scm_version` which relies on [setuptools_scm](https://pypi.org/project/setuptools_scm) to do two things:

- derive the project version from SCM tags
- ensure that all files committed to the repo are automatically included in releases

## Running Tests

The skeleton assumes the developer has [tox](https://pypi.org/project/tox) installed. The developer is expected to run `tox` to run tests on the current Python version using [pytest](https://pypi.org/project/pytest).

Other environments (invoked with `tox -e {name}`) supplied include:

  - a `build-docs` environment to build the documentation
  - a `release` environment to publish the package to PyPI

A pytest.ini is included to define common options around running tests. In particular:

- rely on default test discovery in the current directory
- avoid recursing into common directories not containing tests
- run doctests on modules and invoke flake8 tests
- in doctests, allow unicode literals and regular literals to match, allowing for doctests to run on Python 2 and 3. Also enable ELLIPSES, a default that would be undone by supplying the prior option.
- filters out known warnings caused by libraries/functionality included by the skeleton

Relies a .flake8 file to correct some default behaviors:

- allow tabs for indentation (legacy for jaraco projects)
- disable mutually incompatible rules W503 and W504.

## Continuous Integration

The project is pre-configured to run tests in [Travis-CI](https://travis-ci.org) (.travis.yml). Any new project must be enabled either through their web site or with the `travis enable` command. In addition to running tests, an additional deploy stage is configured to automatically release tagged commits. The username and password for PyPI must be configured for each project using the `travis` command and only after the travis project is created. As releases are cut with [twine](https://pypi.org/project/twine), the two values are supplied through the `TWINE_USERNAME` and `TWINE_PASSWORD`. To configure the latter as a secret, run the following command:

```
echo "TWINE_PASSWORD={password}" | travis encrypt
```

Or disable it in the CI definition and configure it through the web UI.

Features include:
- test against Python 2 and 3
- run on Ubuntu Xenial
- correct for broken IPv6

Also provided is a minimal template for running under Appveyor (Windows).

## Building Documentation

Documentation is automatically built by [Read the Docs](https://readthedocs.org) when the project is registered with it, by way of the .readthedocs.yml file. To test the docs build manually, a tox env may be invoked as `tox -e build-docs`. Both techniques rely on the dependencies declared in `setup.cfg/options.extras_require.docs`.

In addition to building the sphinx docs scaffolded in `docs/`, the docs build a `history.html` file that first injects release dates and hyperlinks into the CHANGES.rst before incorporating it as history in the docs.

## Cutting releases

By default, tagged commits are released through the continuous integration deploy stage.
