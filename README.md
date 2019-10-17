# kong-env

A system for installing Kong Enterprise development versions locally without root access

## Installation

Just `wget` the file or `git clone` the repository down. It should be entirely self contained.

## Usage

```bash
./kong-env.py -v <kong enterprise version>
```

## Notes

 * Currently supported versions include 0.36 and... actually only 0.36 right now.
 * Currently only tested on RHEL7 linux hosts
 * (oddly specific) You'll need /usr/sbin in your path so you can execute `ldconfig`
