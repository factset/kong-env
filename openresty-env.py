#!/usr/bin/env python3

import argparse
import hashlib
import logging
from os import chdir, getcwd, mkdir, path
import subprocess
import sys

logging.basicConfig(level=logging.ERROR, format='%(asctime)-15s: %(message)s')
logger = logging.getLogger(__name__)

lua_version          = '5.1.4'
lua_package_name     = 'lua-' + lua_version
lua_tarball_filename = lua_package_name + '.tar.gz'
lua_tarball_path     = 'https://www.lua.org/ftp/' + lua_tarball_filename
lua_tarball_sha1     = '2b11c8e60306efb7f0734b747588f57995493db7'

openresty_version          = '1.13.6.2'
openresty_package_name     = 'openresty-' + openresty_version
openresty_tarball_filename = openresty_package_name + '.tar.gz'
openresty_tarball_path     = 'https://openresty.org/download/' + openresty_tarball_filename
openresty_tarball_sha1     = '870055f4698168f1f045de92c467a33361dee5d7'

luarocks_version          = '3.1.3'
luarocks_package_name     = 'luarocks-' + luarocks_version
luarocks_tarball_filename = luarocks_package_name + '.tar.gz'
luarocks_tarball_path     = 'https://luarocks.org/releases/' + luarocks_tarball_filename
luarocks_tarball_sha1     = 'f1a9364d31a50bee87765274dde113094337d27b'

class cd:
    """Context manager for changing the current working directory"""
    def __init__(self, newPath):
        self.newPath = path.expanduser(newPath)

    def __enter__(self):
        logger.info('cd\'ing into (%s)' % (self.newPath))
        self.savedPath = getcwd()
        chdir(self.newPath)

    def __exit__(self, etype, value, traceback):
        logger.info('cd\'ing into (%s)' % (self.savedPath))
        chdir(self.savedPath)

def create_directory(environment_directory):
    try:
        mkdir(environment_directory)
    except OSError:
        return False

    return True

def run_command(command_list, verbose):
    logger.info('executing command: ' + ' '.join(command_list))
    if verbose:
        return subprocess.call(command_list) == 0
    return subprocess.call(command_list, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

def validate_hash(filepath, sha1_hash):
    buffer_size = 65536
    sha1 = hashlib.sha1()
    with open(filepath, 'rb') as f:
        while True:
            data = f.read(buffer_size)
            if not data:
                break
            sha1.update(data)

    logger.info('tarball hash (%s), expected hash (%s)' % (sha1.hexdigest(), sha1_hash))
    return sha1.hexdigest() == sha1_hash

def download_and_extract_lua(environment_directory, tmp_directory, verbose):
    with cd(tmp_directory):
        logger.info('running wget for lua package (%s) into directory (%s)' % (lua_tarball_path, tmp_directory))
        if not run_command(['wget', '-q', lua_tarball_path], verbose):
            logger.error('wget failed for path (%s), exiting' % (lua_tarball_path))
            return False

        logger.info('validating lua package hash')
        lua_tarball_file = path.join(tmp_directory, lua_tarball_filename)
        if not validate_hash(lua_tarball_file, lua_tarball_sha1): 
            logger.error('lua tarball hash doesn\'t match, exiting')
            return False

        logger.info('extracting tarball (%s)', lua_tarball_file)
        if not run_command(['tar', '-xf', lua_tarball_file], verbose):
            logger.error('unable to extra tarball (%s), exiting' % (lua_tarball_file))
            return False

    with cd(path.join(tmp_directory, lua_package_name)):
        logger.info('building and installing lua package (%s)' % (lua_package_name))
        if not run_command(['make', 'linux'], verbose):
            logger.error('unable to build lua package (%s)' % (lua_package_name))
            return False
                
        if not run_command(['make', 'install', 'INSTALL_TOP=' + environment_directory], verbose):
            logger.error('unable to install lua package (%s)' % (lua_package_name))
            return False

    return True

def download_and_extract_openresty(environment_directory, tmp_directory, verbose):
    with cd(tmp_directory):
        logger.info('running wget for openresty package (%s) into directory (%s)' % (openresty_tarball_path, tmp_directory))
        if not run_command(['wget', '-q', openresty_tarball_path], verbose):
            logger.error('wget failed for path (%s), exiting' % (openresty_tarball_path))
            return False

        logger.info('validating openresty package hash')
        openresty_tarball_file = path.join(tmp_directory, openresty_tarball_filename)
        if not validate_hash(openresty_tarball_file, openresty_tarball_sha1): 
            logger.error('openresty tarball hash doesn\'t match, exiting')
            return False

        logger.info('extracting tarball (%s)', openresty_tarball_file)
        if not run_command(['tar', '-xf', openresty_tarball_file], verbose):
            logger.error('unable to extra tarball (%s), exiting' % (openresty_tarball_file))
            return False

    with cd(path.join(tmp_directory, openresty_package_name)):
        logger.info('configuring, building and installing openresty package (%s)' % (openresty_package_name))
        shell_command = ['./configure', '--prefix=' + path.join(environment_directory, 'openresty'),
                         '--with-pcre-jit', '--with-http_ssl_module', '--with-http_realip_module',
                         '--with-http_stub_status_module', '--with-http_v2_module']
        if not run_command(['sh', '-c', ' '.join(shell_command)], verbose):
            logger.error('unable to configure openresty package (%s)' % (openresty_package_name))
            return False

        if not run_command(['gmake'], verbose):
            logger.error('unable to build openresty package (%s)' % (openresty_package_name))
            return False
                
        if not run_command(['gmake', 'install'], verbose):
            logger.error('unable to install openresty package (%s)' % (openresty_package_name))
            return False

    return True

def download_and_extract_luarocks(environment_directory, tmp_directory, verbose):
    with cd(tmp_directory):
        logger.info('running wget for luarocks package (%s) into directory (%s)' % (luarocks_tarball_path, tmp_directory))
        if not run_command(['wget', '-q', luarocks_tarball_path], verbose):
            logger.error('wget failed for path (%s), exiting' % (luarocks_tarball_path))
            return False

        logger.info('validating luarocks package hash')
        luarocks_tarball_file = path.join(tmp_directory, luarocks_tarball_filename)
        if not validate_hash(luarocks_tarball_file, luarocks_tarball_sha1): 
            logger.error('luarocks tarball hash doesn\'t match, exiting')
            return False

        logger.info('extracting tarball (%s)', luarocks_tarball_file)
        if not run_command(['tar', '-xf', luarocks_tarball_file], verbose):
            logger.error('unable to extra tarball (%s), exiting' % (luarocks_tarball_file))
            return False

    with cd(path.join(tmp_directory, luarocks_package_name)):
        luajit_directory = path.join(environment_directory, 'openresty', 'luajit')
        luajit_include_directory = path.join(luajit_directory, 'include', 'luajit-2.1')
        shell_command = ['./configure', '--prefix=' + environment_directory, '--lua-version=' + lua_version[0:3],
                         '--with-lua-include=' + luajit_include_directory, '--with-lua=' + luajit_directory]

        logger.info('configuring and installing luarocks package (%s)' % (luarocks_package_name))
        if not run_command(['sh', '-c', ' '.join(shell_command)], verbose):
            logger.error('unable to configure luarocks package (%s)' % (luarocks_package_name))
            return False

        if not run_command(['make', 'install'], verbose):
            logger.error('unable to install luarocks package (%s)' % (luarocks_package_name))
            return False
                
    return True

def create_activation_scripts(environment_directory):
    activation_script = """
if [[ -n "${OPENRESTY_ENV_ACTIVE}" ]]; then
  echo 'error: openresty-env currently activated, can not activate another'
  return
fi

export OLD_PATH=$PATH
export OLD_LD_LIBRARY_PATH=$LD_LIBRARY_PATH
export OLD_LUA_PATH=$LUA_PATH
export OLD_PS1=$PS1
export OPENRESTY_ENV_ACTIVE=1

export PS1="(openresty-env) $PS1"
"""
    bin_directory           = path.join(environment_directory, 'bin')
    openresty_bin_directory = path.join(environment_directory, 'openresty', 'bin')
    luajit_bin_directory    = path.join(environment_directory, 'openresty', 'luajit', 'bin')
    activation_script += 'export PATH=%s:%s:%s:$PATH\n' % (luajit_bin_directory, openresty_bin_directory, bin_directory)

    openresty_luajit_include = path.join(environment_directory, 'openresty', 'luajit', 'share', 'luajit-2.1.0-beta3', '?.lua')
    openresty_lua_include    = path.join(environment_directory, 'openresty', 'luajit', 'share', 'lua', '5.1', '?.lua')
    lua_include = path.join(environment_directory, 'share', 'lua', '5.1', '?.lua')
    activation_script += 'export LUA_PATH="%s;%s;%s"\n' % (openresty_luajit_include, openresty_lua_include, lua_include)
    activation_script += 'alias luarocks=\'luarocks --tree %s\'\n' % (environment_directory)

    with open(path.join(bin_directory, 'activate'), "w") as activate_file:
        activate_file.write(activation_script)

    deactivation_script = """
if [[ -z "${OPENRESTY_ENV_ACTIVE}" ]]; then
  echo 'error: openresty-env not currently activated, so it can not be deactivated'
  return
fi

unalias luarocks
unset OPENRESTY_ENV_ACTIVE
export PATH=$OLD_PATH
export LD_LIBRARY_PATH=$OLD_LD_LIBRARY_PATH
export LUA_PATH=$OLD_LUA_PATH
export PS1=$OLD_PS1
"""
    with open(path.join(bin_directory, 'deactivate'), "w") as deactivate_file:
        deactivate_file.write(deactivation_script)

def cleanup_directory(directory, verbose):
    return run_command(['rm', '-rf', directory], verbose)

def initialize(environment_directory, verbose):
    logger.info('creating environment directory (%s)' % (environment_directory))
    if not create_directory(environment_directory):
        logger.error('unable to create environment (%s), exiting' % (environment_directory))
        sys.exit(1)

    tmp_directory = path.join(environment_directory, 'tmp')
    if not create_directory(tmp_directory):
        logger.error('unable to create temporary installation directory (%s), exiting' % (tmp_directory))
        sys.exit(1)

    logger.info('downloading lua: version (%s)' % (lua_version))
    if not download_and_extract_lua(environment_directory, tmp_directory, verbose):
        sys.exit(1)

    logger.info('downloading openresty: version (%s)' % (openresty_version))
    if not download_and_extract_openresty(environment_directory, tmp_directory, verbose):
        sys.exit(1)

    logger.info('downloading luarocks: version (%s)' % (luarocks_version))
    if not download_and_extract_luarocks(environment_directory, tmp_directory, verbose):
        sys.exit(1)

    logger.info('creating activation scripts')
    if not create_activation_scripts(environment_directory):
        sys.exit(1)

    logger.info('cleaning up temp directory')
    if not cleanup_directory(tmp_directory, verbose):
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Initializes a local Openresty development environment')
    parser.add_argument('--environment', '-e', required=True, help='The Openresty environment name')
    parser.add_argument('--verbose', '-v', help='Optional: Specifies verbose logger', action='store_true')
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.INFO)

    environment_directory = path.abspath(path.join('.', args.environment))
    if path.isdir(environment_directory):
        logger.error('environment (%s) already exists. exiting' % (args.environment))
        sys.exit(1)

    logger.info('initializing openresty environment (%s)' % (args.environment))
    initialize(environment_directory, args.verbose)

if __name__ == "__main__":
    main()
