# OSSTREA

OSSTREA (**O**pen **S**ource **S**oftware pa**T**ent **R**isk **E**valuation **A**ssistance) is a tool to help evaluate risk of patents contained within OSS.

## Set Up
This software has been tested on Ubuntu 24.04 (other environments will be supported in the future).

It also requires **Python `3.12`** or higher.

`database.json` is not included in this repository. You need to prepare it yourself and place it at `database/database.json` in the project root (create the `database/` directory if needed) before installing.

The tool also runs with an empty database, but then there is no patent data to check against, so the results are not meaningful. To start with an empty one, create `database/database.json` with the following content:
```json
{"packages": [], "usage_histories": [], "consultation_histories": []}
```

You can install this tool in editable mode by executing the following command in the project root:
```shell-session
pip3 install -e .
```

Editable mode is required: OSSTREA locates `database/` relative to the project root, so the tool must keep running from this directory. A regular `pip3 install .` copies the package into `site-packages`, where `database/database.json` cannot be found.

If the installation is successful, you should be able to verify the current version of OSSTREA by running the following command:
```shell-session
osstrea --version
```

## Usage
If you just run the software, run:
```shell-session
osstrea check YOUR_SBOM_PATH
```

Run `osstrea --help` for the list of subcommands and options.

Incidentally, the program no longer has access to the URL it was using (e.g. [Table 11](https://openinventionnetwork.com/linux-system/table-11/)), so it can no longer function properly, unfortunately.

# Uninstall

You can uninstall this tool by executing the following command:
```shell-session
pip3 uninstall osstrea
```

# Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md).

# License
This project is licensed under the Apache License 2.0. See [LICENSE.md](LICENSE.md).
