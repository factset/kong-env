#!/usr/bin/env python3

import argparse
import hashlib
import logging
from os import chdir, getcwd, mkdir, path
import subprocess
import sys

logging.basicConfig(level=logging.INFO, format='%(asctime)-15s: %(message)s')
logger = logging.getLogger(__name__)

LIBYAML_HOSTPATH   = 'http://pyyaml.org/download/libyaml/'
LUA_HOSTPATH       = 'https://www.lua.org/ftp/'
OPENRESTY_HOSTPATH = 'https://openresty.org/download/'
LUAROCKS_HOSTPATH  = 'https://luarocks.org/releases/'

CONFIG = {
    '0.36' : {
        'busted' : {
            'version' : '2.0.0'
        },
        'kong-community' : {
            'version' : '1.2.1'
        },
        'libyaml' : {
            'version' : '0.2.2',
            'package' : 'yaml-0.2.2',
            'tarball' : 'yaml-0.2.2.tar.gz',
            'sha1'    : 'ef3b86ba000319913e3fa2976657a1d43b353536'
        },
        'lyaml' : {
            'version' : '6.2.3'
        },
        'lua' : {
            'version' : '5.1.4',
            'package' : 'lua-5.1.4',
            'tarball' : 'lua-5.1.4.tar.gz',
            'sha1'    : '2b11c8e60306efb7f0734b747588f57995493db7'
        },
        'luarocks' : {
            'version' : '3.2.1',
            'package' : 'luarocks-3.2.1',
            'tarball' : 'luarocks-3.2.1.tar.gz',
            'sha1'    : '19483c7add5ef64f7e70992544cba7d4c4f6d4ae'
        },
        'openresty' : {
            'version'        : '1.15.8.1',
            'package'        : 'openresty-1.15.8.1',
            'tarball'        : 'openresty-1.15.8.1.tar.gz',
            'sha1'           : 'cb8cb132f06c9618bdbe57f5e16f4d9d513a6fe3',
            'luajit_version' : '2.1',
            'luajit_package' : 'luajit-2.1.0-beta3'
        }
    }
}

class cd:
    """Context manager for changing the current working directory"""
    def __init__(self, newPath):
        self.newPath = path.expanduser(newPath)

    def __enter__(self):
        logger.debug('cd\'ing into (%s)' % (self.newPath))
        self.savedPath = getcwd()
        chdir(self.newPath)

    def __exit__(self, etype, value, traceback):
        logger.debug('cd\'ing into (%s)' % (self.savedPath))
        chdir(self.savedPath)

def create_directory(environment_directory):
    try:
        mkdir(environment_directory)
    except OSError:
        return False

    return True

def run_command(command_list, verbose):
    logger.debug('executing command: ' + ' '.join(command_list))
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

    logger.debug('tarball hash (%s), expected hash (%s)' % (sha1.hexdigest(), sha1_hash))
    return sha1.hexdigest() == sha1_hash

def download_and_extract_lua(environment_directory, tmp_directory, config, verbose):
    with cd(tmp_directory):
        logger.info('running wget for lua package (%s) into directory (%s)' % (config['package'], tmp_directory))
        tarball_url = LUA_HOSTPATH + config['tarball']
        if not run_command(['wget', '-q', tarball_url], verbose):
            logger.error('wget failed for path (%s), exiting' % (lua_tarball_path))
            return False

        logger.info('validating lua tarball (%s) hash' % (config['tarball']))
        lua_tarball_file = path.join(tmp_directory, config['tarball'])
        if not validate_hash(lua_tarball_file, config['sha1']): 
            logger.error('lua tarball hash doesn\'t match, exiting')
            return False

        logger.info('extracting tarball (%s) into directory (%s)' % (config['tarball'], tmp_directory))
        if not run_command(['tar', '-xf', lua_tarball_file], verbose):
            logger.error('unable to extract tarball (%s), exiting' % (lua_tarball_file))
            return False

    with cd(path.join(tmp_directory, config['package'])):
        logger.info('building and installing lua package (%s)' % (config['package']))
        if not run_command(['make', 'linux'], verbose):
            logger.error('unable to build lua package (%s)' % (config['package']))
            return False
                
        if not run_command(['make', 'install', 'INSTALL_TOP=' + environment_directory], verbose):
            logger.error('unable to install lua package (%s)' % (config['package']))
            return False

    return True

def download_and_extract_openresty(environment_directory, tmp_directory, config, verbose):
    with cd(tmp_directory):
        logger.info('running wget for openresty package (%s) into directory (%s)' % (config['package'], tmp_directory))
        tarball_url = OPENRESTY_HOSTPATH + config['tarball']
        if not run_command(['wget', '-q', tarball_url], verbose):
            logger.error('wget failed for path (%s), exiting' % (openresty_tarball_path))
            return False

        logger.info('validating openresty tarball (%s) hash' % (config['tarball']))
        openresty_tarball_file = path.join(tmp_directory, config['tarball'])
        if not validate_hash(openresty_tarball_file, config['sha1']): 
            logger.error('openresty tarball hash doesn\'t match, exiting')
            return False

        logger.info('extracting tarball (%s) into directory (%s)', config['tarball'], tmp_directory)
        if not run_command(['tar', '-xf', openresty_tarball_file], verbose):
            logger.error('unable to extract tarball (%s), exiting' % (openresty_tarball_file))
            return False

    with cd(path.join(tmp_directory, config['package'])):
        logger.info('configuring openresty package (%s)' % (config['package']))
        shell_command = ['./configure', '--prefix=' + path.join(environment_directory, 'openresty'),
                         '--with-pcre-jit', '--with-http_ssl_module', '--with-http_realip_module',
                         '--with-http_stub_status_module', '--with-http_v2_module']
        if not run_command(['sh', '-c', ' '.join(shell_command)], verbose):
            logger.error('unable to configure openresty package (%s)' % (config['package']))
            return False
 
        logger.info('compiling openresty package (%s)' % (config['package']))
        if not run_command(['gmake'], verbose):
            logger.error('unable to build openresty package (%s)' % (config['package']))
            return False
                
        logger.info('installing openresty package (%s)' % (config['package']))
        if not run_command(['gmake', 'install'], verbose):
            logger.error('unable to install openresty package (%s)' % (config['package']))
            return False

    return True

def download_and_extract_luarocks(environment_directory, tmp_directory, config, lua_version, luajit_version, verbose):
    with cd(tmp_directory):
        logger.info('running wget for luarocks package (%s) into directory (%s)' % (config['package'], tmp_directory))
        tarball_url = LUAROCKS_HOSTPATH + config['tarball']
        if not run_command(['wget', '-q', tarball_url], verbose):
            logger.error('wget failed for path (%s), exiting' % (luarocks_tarball_path))
            return False

        logger.info('validating luarocks package (%s) hash' % (config['package']))
        luarocks_tarball_file = path.join(tmp_directory, config['tarball'])
        if not validate_hash(luarocks_tarball_file, config['sha1']): 
            logger.error('luarocks tarball hash doesn\'t match, exiting')
            return False

        logger.info('extracting tarball (%s) into directory (%s)' % (config['tarball'], tmp_directory))
        if not run_command(['tar', '-xf', luarocks_tarball_file], verbose):
            logger.error('unable to extract tarball (%s), exiting' % (luarocks_tarball_file))
            return False

    with cd(path.join(tmp_directory, config['package'])):
        luajit_package = 'luajit-' + luajit_version
        luajit_directory = path.join(environment_directory, 'openresty', 'luajit')
        luajit_include_directory = path.join(luajit_directory, 'include', luajit_package)
        shell_command = ['./configure', '--prefix=' + environment_directory, '--lua-version=' + lua_version[0:3],
                         '--with-lua-include=' + luajit_include_directory, '--with-lua=' + luajit_directory]

        logger.info('configuring luarocks: package (%s), lua (%s), luajit (%s)' % (config['package'], lua_version, luajit_version))
        if not run_command(['sh', '-c', ' '.join(shell_command)], verbose):
            logger.error('unable to configure luarocks package (%s)' % (config['package']))
            return False

        logger.info('installing luarocks package (%s)' % (config['version']))
        if not run_command(['make', 'install'], verbose):
            logger.error('unable to install luarocks package (%s)' % (config['package']))
            return False
                
    return True

def download_and_extract_libyaml(environment_directory, tmp_directory, config, verbose):
    with cd(tmp_directory):
        logger.info('running wget for libyaml package (%s) into directory (%s)' % (config['package'], tmp_directory))
        tarball_url = LIBYAML_HOSTPATH + config['tarball']
        if not run_command(['wget', '-q', tarball_url], verbose):
            logger.error('wget failed for path (%s), exiting' % (libyaml_tarball_path))
            return False

        logger.info('validating libyaml tarball (%s) hash' % (config['tarball']))
        libyaml_tarball_file = path.join(tmp_directory, config['tarball'])
        if not validate_hash(libyaml_tarball_file, config['sha1']): 
            logger.error('libyaml tarball hash doesn\'t match, exiting')
            return False

        logger.info('extracting tarball (%s) into directory (%s)', config['tarball'], tmp_directory)
        if not run_command(['tar', '-xf', libyaml_tarball_file], verbose):
            logger.error('unable to extract tarball (%s), exiting' % (libyaml_tarball_file))
            return False

    with cd(path.join(tmp_directory, config['package'])):
        logger.info('configuring libyaml package (%s)' % (config['package']))
        shell_command = ['./configure', '--prefix=' + environment_directory]
        if not run_command(['sh', '-c', ' '.join(shell_command)], verbose):
            logger.error('unable to configure openresty package (%s)' % (config['package']))
            return False
 
        logger.info('compiling libyaml package (%s)' % (config['package']))
        if not run_command(['make'], verbose):
            logger.error('unable to build openresty package (%s)' % (config['package']))
            return False
                
        logger.info('installing libyaml package (%s)' % (config['package']))
        if not run_command(['make', 'install'], verbose):
            logger.error('unable to install libyaml package (%s)' % (config['package']))
            return False

    return True

def install_lyaml_luarock(environment_directory, config, verbose):
    luarocks_bin = path.join(environment_directory, 'bin', 'luarocks')

    # The build system for lyaml, this custom system called luke, for which lyaml
    # uses a bleeding edge, minified version of, doesn't find libyaml correctly. If you
    # follow its advice and specify YAML_DIR, it effectively ignores that. In order
    # to get it to find libyaml correctly, I need to force the appropriate of -L and -I
    # directives into the mercifully overridable C and LIB flags, so that it looks
    # for the locally built version of the library. -styree
    include_path = '-I' + path.join(environment_directory, 'include')
    lib_path     = '-L' + path.join(environment_directory, 'lib')
    command = [luarocks_bin, 'install', '--tree', environment_directory, 'lyaml', config['version'],
               'CFLAGS=-O2 -fPIC %s %s' % (include_path, lib_path),
               'LIBFLAG=-shared %s' % (lib_path),
               'YAML_DIR=%s' % (environment_directory)]
    logger.info('installing lyaml version (%s) via luarocks' % (config['version']))
    if not run_command(command, verbose):
        logger.error('unable to luarocks install lyaml version (%s)' % (['version']))
        return False

    return True

def install_busted_luarock(environment_directory, config, verbose):
    luarocks_bin = path.join(environment_directory, 'bin', 'luarocks')
    logger.info('installing busted version (%s) via luarocks' % (config['version']))
    if not run_command([luarocks_bin, 'install', '--tree', environment_directory, 'busted', config['version']], verbose):
        logger.error('unable to luarocks install busted version (%s), exiting' % (config['version']))
        return False

    return True

def install_kong_luarock(environment_directory, config, verbose):
    luarocks_bin = path.join(environment_directory, 'bin', 'luarocks')
    logger.info('installing kong community version (%s) via luarocks' % (config['version']))
    if not run_command([luarocks_bin, 'install', '--tree', environment_directory, 'kong', config['version']], verbose):
        logger.error('unable to luarocks install kong version (%s), exiting' % (config['version']))
        return False

    return True

def create_activation_scripts(environment_directory, kong_version, lua_version, luajit_package):
    activation_script = """
if [[ -n "${KONG_ENV_ACTIVE}" ]]; then
  echo 'error: kong-env currently activated, can not activate another'
  return
fi

export KONG_ENV_ACTIVE=1
export OLD_PATH=$PATH
export OLD_LD_LIBRARY_PATH=$LD_LIBRARY_PATH
export OLD_LUA_PATH=$LUA_PATH
export OLD_PS1=$PS1
""" 
    bin_directory           = path.join(environment_directory, 'bin')
    openresty_bin_directory = path.join(environment_directory, 'openresty', 'bin')
    luajit_bin_directory    = path.join(environment_directory, 'openresty', 'luajit', 'bin')
    activation_script += 'export PATH=%s:%s:%s:$PATH\n' % (luajit_bin_directory, openresty_bin_directory, bin_directory)

    openresty_luajit_include = path.join(environment_directory, 'openresty', 'luajit', 'share', luajit_package, '?.lua')
    openresty_lua_include    = path.join(environment_directory, 'openresty', 'luajit', 'share', 'lua', lua_version[0:3], '?.lua')
    lua_include = path.join(environment_directory, 'share', 'lua', lua_version[0:3], '?.lua')
    activation_script += 'export LUA_PATH="%s;%s;%s"\n' % (openresty_luajit_include, openresty_lua_include, lua_include)
    activation_script += 'alias luarocks=\'luarocks --tree %s\'\n' % (environment_directory)

    ps1_prefix = '(kong-%s)' % (kong_version)
    activation_script += 'export PS1="%s $PS1"\n' % (ps1_prefix)

    lib_directory      = path.join(environment_directory, 'lib')
    activation_script += 'export LD_LIBRARY_PATH=%s:$LD_LIBRARY_PATH\n' % (lib_directory)

    with open(path.join(bin_directory, 'activate'), "w") as activate_file:
        activate_file.write(activation_script)

    deactivation_script = """
if [[ -z "${KONG_ENV_ACTIVE}" ]]; then
  echo 'error: openresty-env not currently activated, so it can not be deactivated'
  return
fi

unalias luarocks
unset KONG_ENV_ACTIVE
export PATH=$OLD_PATH
export LD_LIBRARY_PATH=$OLD_LD_LIBRARY_PATH
export LUA_PATH=$OLD_LUA_PATH
export PS1=$OLD_PS1
"""
    with open(path.join(bin_directory, 'deactivate'), "w") as deactivate_file:
        deactivate_file.write(deactivation_script)

def cleanup_directory(directory, verbose):
    return run_command(['rm', '-rf', directory], verbose)

def initialize(environment_directory, kong_config, kong_version, verbose):
    logger.info('creating environment directory (%s)' % (environment_directory))
    if not create_directory(environment_directory):
        logger.error('unable to create environment (%s), exiting' % (environment_directory))
        sys.exit(1)

    tmp_directory = path.join(environment_directory, 'tmp')
    logger.info('creating temporary directory (%s)' % (tmp_directory))
    if not create_directory(tmp_directory):
        logger.error('unable to create temporary directory (%s), exiting' % (tmp_directory))
        sys.exit(1)

    lua_config = kong_config['lua']
    logger.info('downloading and extracting lua: version (%s)' % (lua_config['version']))
    if not download_and_extract_lua(environment_directory, tmp_directory, lua_config, verbose):
        sys.exit(1)

    openresty_config = kong_config['openresty']
    logger.info('downloading and extracting openresty: version (%s)' % (openresty_config['version']))
    if not download_and_extract_openresty(environment_directory, tmp_directory, openresty_config, verbose):
        sys.exit(1)

    luarocks_config = kong_config['luarocks']
    logger.info('downloading and extracting luarocks: version (%s)' % (luarocks_config['version']))
    if not download_and_extract_luarocks(environment_directory, tmp_directory, luarocks_config,
                                         lua_config['version'], openresty_config['luajit_version'], verbose):
        sys.exit(1)

    libyaml_config = kong_config['libyaml']
    logger.info('downloading and extracting libyaml: version (%s)' % (libyaml_config['version']))
    if not download_and_extract_libyaml(environment_directory, tmp_directory, libyaml_config, verbose):
        sys.exit(1)

    lyaml_config = kong_config['lyaml']
    logger.info('installing lyaml luarock: version (%s)' % (lyaml_config['version']))
    if not install_lyaml_luarock(environment_directory, lyaml_config, verbose):
        sys.exit(1)

    busted_config = kong_config['busted']
    logger.info('installing busted luarock: version (%s)' % (busted_config['version']))
    if not install_busted_luarock(environment_directory, busted_config, verbose):
        sys.exit(1)

    kong_community_config = kong_config['kong-community']
    logger.info('installing kong community luarock: version (%s)' % (kong_community_config['version']))
    if not install_kong_luarock(environment_directory, kong_community_config, verbose):
        sys.exit(1)

    logger.info('creating activation scripts')
    if not create_activation_scripts(environment_directory, kong_version, lua_config['version'], openresty_config['luajit_package']):
        sys.exit(1)

    logger.info('cleaning up temp directory')
    if not cleanup_directory(tmp_directory, verbose):
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Initializes a local Kong development environment')
    parser.add_argument('--version', '-v', required=True, help='The Kong Enterprise Edition version')
    parser.add_argument('--verbose', help='Optional: Specifies verbose logger', action='store_true')
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if args.version not in CONFIG:
        logger.error('Specified Kong Enterprise version (%s) not supported, exiting' % (args.version))
        sys.exit(1)
    kong_config = CONFIG[args.version]

    environment_directory = path.abspath(path.join('.', 'kong-' + args.version))
    if path.isdir(environment_directory):
        logger.error('kong environment (%s) already exists. exiting' % (args.version))
        sys.exit(1)

    logger.info('initializing kong environment for enterprise version (%s)' % (args.version))
    initialize(environment_directory, kong_config, args.version, args.verbose)

if __name__ == "__main__":
    main()
