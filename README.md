# kong-env

A system for installing a Kong-Enterprise compatible development environment locally without root access

## Why?

Kong supports various methods for developing custom plugins, namely [Vagrant](https://github.com/Kong/kong-vagrant) and [Docker](https://docs.konghq.com/install/docker/), but those methods don't work in environment where you are either not allowed to use VM's (by corporate policy or permissions) or you don't have sudo access. In these constrained environments you might need to locally install all of your dependencies and configuration, which existing solution don't support conveniently.

The closest approximation to this tool is the [openresty-build-tools repository](https://github.com/Kong/openresty-build-tools) managed by Kong, but that tool doesn't manage which version of each package you need for the appropriate enterprise edition of Kong, it doesn't perform a local luarocks install of all needed dependencies of Kong, and it doesn't provide facilities for attaching to and detaching from the local environment, akin to how Python virtual environments allow you to do.

## Installation

Just `wget` the file or `git clone` the repository down. It is a self contained script.

## Usage

Creating a kong environment is fairly straightforward through calling the script with the appropriate Kong Enterprise version:

```bash
./kong-env.py -v <kong enterprise version>
```

Attaching to that Kong environment is as simple as calling the embedded activate script:

```bash
. kong-<kong enterprise version>/bin/activate
```

Doing so will set PS1 to let you know you're attached to the environment, and will add all appropriate binaries, libraries and lua scripts to the appropriate paths. To detach from a kong environment, just call the associated deactivate script:

```bash
. kong-<kong enterprise version>/bin/deactivate
```

## Requirements

 * Python 3.4+

## License

    Copyright 2019 FactSet Research Systems Inc.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
