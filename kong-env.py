#!/usr/bin/env python3

import argparse
import hashlib
import json
import logging
from os import chdir, getcwd, mkdir, path
import subprocess
import sys

logging.basicConfig(level=logging.INFO, format='%(asctime)-15s: %(message)s')
logger = logging.getLogger(__name__)

LIBYAML_HOSTPATH           = 'http://pyyaml.org/download/libyaml/'
LUA_KONG_NGINX_MODULE_REPO = 'https://github.com/Kong/lua-kong-nginx-module'
OPENRESTY_HOSTPATH         = 'https://openresty.org/download/'
OPENRESTY_PATCHES_URL      = 'https://github.com/Kong/openresty-patches/archive/master.tar.gz'
OPENRESTY_PATCHES_TARBALL  = 'master.tar.gz'
OPENSSL_HOSTPATH           = 'https://www.openssl.org/source/'
PCRE_HOSTPATH              = 'https://ftp.pcre.org/pub/pcre/'
LUAROCKS_HOSTPATH          = 'https://luarocks.org/releases/'

CONFIG = {
    '0.35' : {
        'kong-community' : {
            'version' : '1.0.3'
        },
        'libyaml' : {
            'version' : '0.2.2',
            'sha1'    : 'ef3b86ba000319913e3fa2976657a1d43b353536'
        },
        'luarocks' : {
            'version' : '3.1.3',
            'sha1'    : 'f1a9364d31a50bee87765274dde113094337d27b'
        },
        'openresty' : {
            'version'        : '1.13.6.2',
            'sha1'           : '870055f4698168f1f045de92c467a33361dee5d7',
            'luajit_version' : '2.1',
            'luajit_package' : 'luajit-2.1.0-beta3',
            'lua_version'    : '5.1'
        },
        'openssl' : {
            'version': '1.1.0l',
            'sha1'   : '6e3507b29e2630f56023887d1f7d7ba1f584819b'
        },
        'pcre' : {
            'version': '8.41',
            'sha1'   : 'dddf0995aefe04cc6267c1448ffef0e7b0560ec0'
        }
    },
    '0.36' : {
        'kong-community' : {
            'version' : '1.2.1'
        },
        'libyaml' : {
            'version' : '0.2.2',
            'sha1'    : 'ef3b86ba000319913e3fa2976657a1d43b353536'
        },
        'luarocks' : {
            'version' : '3.1.3',
            'sha1'    : 'f1a9364d31a50bee87765274dde113094337d27b'
        },
        'openresty' : {
            'version'        : '1.13.6.2',
            'sha1'           : '870055f4698168f1f045de92c467a33361dee5d7',
            'luajit_version' : '2.1',
            'luajit_package' : 'luajit-2.1.0-beta3',
            'lua_version'    : '5.1'
        },
        'openssl' : {
            'version': '1.1.0l',
            'sha1'   : '6e3507b29e2630f56023887d1f7d7ba1f584819b'
        },
        'pcre' : {
            'version': '8.41',
            'sha1'   : 'dddf0995aefe04cc6267c1448ffef0e7b0560ec0'
        }
    },
    '1.3' : {
        'kong-community' : {
            'version' : '1.3.0'
        },
        'lua-kong-nginx-module' : {
            'version' : '0.0.4'
        },
        'libyaml' : {
            'version' : '0.2.2',
            'sha1'    : 'ef3b86ba000319913e3fa2976657a1d43b353536'
        },
        'luarocks' : {
            'version' : '3.1.3',
            'sha1'    : 'f1a9364d31a50bee87765274dde113094337d27b'
        },
        'openresty' : {
            'version'        : '1.15.8.1',
            'sha1'           : 'cb8cb132f06c9618bdbe57f5e16f4d9d513a6fe3',
            'luajit_version' : '2.1',
            'luajit_package' : 'luajit-2.1.0-beta3',
            'lua_version'    : '5.1'
        },
        'openssl' : {
            'version': '1.1.1c',
            'sha1'   : '71b830a077276cbeccc994369538617a21bee808'
        },
        'pcre' : {
            'version': '8.41',
            'sha1'   : 'dddf0995aefe04cc6267c1448ffef0e7b0560ec0'
        }
    }
}

class cd:
    """Context manager for changing the current working directory"""
    def __init__(self, newPath):
        self.newPath = path.expanduser(newPath)

    def __enter__(self):
        logger.debug('cd: path=%s' % (self.newPath))
        self.savedPath = getcwd()
        chdir(self.newPath)

    def __exit__(self, etype, value, traceback):
        logger.debug('cd: path=%s' % (self.savedPath))
        chdir(self.savedPath)

def create_directory(environment_directory):
    try:
        mkdir(environment_directory)
    except OSError:
        return False

    return True

def run_command(command_list, verbose):
    logger.debug('running command: command=' + ' '.join(command_list))

    close_fds=True
    if command_list[0] in ('make', 'gmake'):
        # honor parallel make, jobserver needs open fds
        close_fds=False

    if verbose:
        return subprocess.call(command_list, close_fds=close_fds) == 0
    return subprocess.call(command_list, close_fds=close_fds, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

def run_patch_files(openresty_version, verbose):
    command = 'for i in ../../openresty-patches-master/patches/%s/*.patch; do patch -p1 < $i; done' % (openresty_version)
    logger.debug('patching files: command=' + command)
    if verbose:
        return subprocess.call([command], shell=True) == 0
    return subprocess.call([command], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True) == 0

def validate_hash(filepath, sha1_hash):
    buffer_size = 65536
    sha1 = hashlib.sha1()
    with open(filepath, 'rb') as f:
        while True:
            data = f.read(buffer_size)
            if not data:
                break
            sha1.update(data)

    logger.debug('tarball hash comparison: value=%s expected=%s' % (sha1.hexdigest(), sha1_hash))
    return sha1.hexdigest() == sha1_hash

def package_name(package, version):
    return package + '-' + version

def tarball_name(package, version):
    return package_name(package, version) + '.tar.gz'

def download_and_extract_openssl(environment_directory, tmp_directory, config, verbose):
    package = package_name('openssl', config['version'])
    tarball = tarball_name('openssl', config['version'])

    with cd(tmp_directory):
        logger.debug('fetching openssl package into temp directory: package=%s directory=%s' % (package, tmp_directory))
        tarball_url = OPENSSL_HOSTPATH + tarball
        if not run_command(['wget', '-q', tarball_url], verbose):
            logger.error('wget failed, exiting: url=%s directory=%s' % (tarball, tmp_directory))
            return False

        logger.debug('validating openssl tarball hash: tarball=%s' % (tarball))
        openssl_tarball_file = path.join(tmp_directory, tarball)
        if not validate_hash(openssl_tarball_file, config['sha1']): 
            logger.error('tarball hash doesn\'t match, exiting')
            return False

        logger.debug('extracting tarball: tarball=%s directory=%s' % (tarball, tmp_directory))
        if not run_command(['tar', '-xf', openssl_tarball_file], verbose):
            logger.error('unable to extract tarball, exiting: tarball=%s' % (openssl_tarball_file))
            return False

    with cd(path.join(tmp_directory, package)):
        logger.debug('configuring openssl package: package=%s' % (package))
        shell_command = ['./Configure', 'linux-x86_64', 'no-unit-test',
                         '--prefix=' + environment_directory, '--openssldir=' + environment_directory]
        if not run_command(['sh', '-c', ' '.join(shell_command)], verbose):
            logger.error('unable to configure openssl package, exiting: package=%s' % (package))
            return False

        logger.debug('building openssl package: package=%s' % (package))
        if not run_command(['make'], verbose):
            logger.error('unable to build openssl package, exiting: package=%s' % (package))
            return False

        logger.debug('installing openssl package: package=%s' % (package))
        if not run_command(['make', 'install_sw', '-j1'], verbose): # force being non-parallel for just this step
            logger.error('unable to install openssl package, exiting: package=%s' % (package))
            return False

    return True

def download_and_extract_pcre(environment_directory, tmp_directory, config, verbose):
    package = package_name('pcre', config['version'])
    tarball = tarball_name('pcre', config['version'])

    with cd(tmp_directory):
        logger.debug('fetching pcre package into temp directory: package=%s directory=%s' % (package, tmp_directory))
        tarball_url = PCRE_HOSTPATH + tarball
        if not run_command(['wget', '-q', tarball_url], verbose):
            logger.error('wget failed, exiting: url=%s, directory=%s' % (tarball_url, tmp_directory))
            return False

        logger.debug('validating pcre tarball hash: tarball=%s' % (tarball))
        pcre_tarball_file = path.join(tmp_directory, tarball)
        if not validate_hash(pcre_tarball_file, config['sha1']): 
            logger.error('tarball hash doesn\'t match, exiting')
            return False

        logger.debug('extracting tarball: tarball=%s directory=%s' % (tarball, tmp_directory))
        if not run_command(['tar', '-xf', pcre_tarball_file], verbose):
            logger.error('unable to extract tarball, exiting: tarball=%s' % (pcre_tarball_file))
            return False

    return True

def download_lua_kong_nginx_module(environment_directory, tmp_directory, lua_kong_nginx_module_config, verbose):
    with cd(tmp_directory):
        module_version = lua_kong_nginx_module_config['version']
        logger.debug('git clone\'ing lua-kong-nginx-module: version=%s' % (module_version))
        if not run_command(['git', 'clone', '--branch', module_version, LUA_KONG_NGINX_MODULE_REPO, 'lua-kong-nginx-module'], verbose):
            logger.error('unable to clone lua-kong-nginx-module repository: version=%s' % (module_version))
            return False

    return True

def download_and_extract_openresty(environment_directory, tmp_directory, config, pcre_package, lua_kong_nginx_module_config, verbose):
    package = package_name('openresty', config['version'])
    tarball = tarball_name('openresty', config['version'])

    with cd(tmp_directory):
        tarball_url = OPENRESTY_HOSTPATH + tarball
        logger.debug('fetching openresty tarball: url=%s directory=%s' % (tarball_url, tmp_directory))
        if not run_command(['wget', '-q', tarball_url], verbose):
            logger.error('wget failed, exiting: url=%s directory=%s'  % (tarball_url, tmp_directory))
            return False

        logger.debug('validating tarball hash: tarball=%s' % (tarball))
        openresty_tarball_file = path.join(tmp_directory, tarball)
        if not validate_hash(openresty_tarball_file, config['sha1']): 
            logger.error('tarball hash doesn\'t match, exiting')
            return False

        logger.debug('extracting tarball: tarball=%s directory=%s', tarball, tmp_directory)
        if not run_command(['tar', '-xf', openresty_tarball_file], verbose):
            logger.error('unable to extract tarball, exiting: tarball=%s' % (openresty_tarball_file))
            return False

        logger.debug('fetching kong openresty patch tarball: url=%s directory=%s' % (OPENRESTY_PATCHES_URL, tmp_directory))
        if not run_command(['wget', OPENRESTY_PATCHES_URL], verbose):
            logger.error('wget failed, exiting: url=%s' % (OPENRESTY_PATCHES_URL))
            return False

        logger.debug('extracting tarball: tarball=%s directory=%s' % (OPENRESTY_PATCHES_TARBALL, tmp_directory))
        if not run_command(['tar', '-xf', OPENRESTY_PATCHES_TARBALL], verbose):
            logger.error('unable to extract tarball, exiting: tarball=%s' % (OPENRESTY_PATCHES_TARBALL))
            return False

    logger.debug('applying kong openresty patches: version=%s' % (config['version']))
    with cd(path.join(tmp_directory, package, 'bundle')):
        if not run_patch_files(config['version'], verbose):
            logger.error('unable to apply patches for openresty, exiting: version=%s' % (config['version']))
            return False

    with cd(path.join(tmp_directory, package)):
        logger.debug('configuring openresty package: package=%s' % (package))
        shell_command = ['./configure', '--prefix=' + path.join(environment_directory, 'openresty'),
                         '--with-pcre-jit', '--with-pcre=' + path.join(tmp_directory, pcre_package),
                         '--with-http_ssl_module', '--with-http_realip_module',
                         '--with-http_stub_status_module', '--with-http_v2_module',
                         '--with-cc-opt="-I' + path.join(environment_directory, 'include') + '"',
                         '--with-luajit-xcflags="-DLUAJIT_NUMMODE=2"', '-j8',
                         '--with-stream_ssl_preread_module', '--with-stream_realip_module']
        if lua_kong_nginx_module_config is not None:
            shell_command.append('--add-module=' + path.join(tmp_directory, 'lua-kong-nginx-module'))

        ld_opt_prefix = '--with-ld-opt="-L' + path.join(environment_directory, 'lib')
        if config['version'] == '1.15.8.1':
            # This openresty version builds a static libpcre poorly, so we need a workaround
            # See - https://github.com/openresty/lua-resty-core/issues/258
            shell_command.append(ld_opt_prefix + ' -Wl,-u,pcre_version"')
        else:
            shell_command.append(ld_opt_prefix + '"')

        if not run_command(['sh', '-c', ' '.join(shell_command)], verbose):
            logger.error('unable to configure openresty package, exiting: package=%s' % (package))
            return False

        logger.debug('compiling openresty: package=%s' % (package))
        if not run_command(['gmake'], verbose):
            logger.error('unable to build openresty package, exiting: package=%s' % (package))
            return False

        logger.debug('installing openresty: package=%s' % (package))
        if not run_command(['gmake', 'install'], verbose):
            logger.error('unable to install openresty package, exiting: package=%s' % (package))
            return False

    return True

def download_and_extract_luarocks(environment_directory, tmp_directory, config, lua_version, luajit_version, verbose):
    package = package_name('luarocks', config['version'])
    tarball = tarball_name('luarocks', config['version'])

    with cd(tmp_directory):
        tarball_url = LUAROCKS_HOSTPATH + tarball
        logger.debug('fetching luarocks tarball: url=%s directory=%s' % (tarball_url, tmp_directory))
        if not run_command(['wget', '-q', tarball_url], verbose):
            logger.error('wget failed, exiting: url=%s directory=%s' % (tarball_url, tmp_directory))
            return False

        logger.debug('validating tarball hash: tarball=%s' % (tarball))
        luarocks_tarball_file = path.join(tmp_directory, tarball)
        if not validate_hash(luarocks_tarball_file, config['sha1']): 
            logger.error('tarball hash doesn\'t match, exiting')
            return False

        logger.debug('extracting tarball: tarball=%s directory=%s' % (tarball, tmp_directory))
        if not run_command(['tar', '-xf', luarocks_tarball_file], verbose):
            logger.error('unable to extract tarball, exiting: tarball=%s' % (luarocks_tarball_file))
            return False

    with cd(path.join(tmp_directory, package)):
        luajit_package = 'luajit-' + luajit_version
        luajit_directory = path.join(environment_directory, 'openresty', 'luajit')
        luajit_include_directory = path.join(luajit_directory, 'include', luajit_package)
        shell_command = ['./configure', '--prefix=' + environment_directory, '--lua-version=' + lua_version[0:3],
                         '--with-lua-include=' + luajit_include_directory, '--with-lua=' + luajit_directory]

        logger.debug('configuring luarocks: package=%s lua-version=%s luajit-version=%s' % (package, lua_version,
                                                                                            luajit_version))
        if not run_command(['sh', '-c', ' '.join(shell_command)], verbose):
            logger.error('unable to configure luarocks, exiting: package=%s' % (package))
            return False

        logger.debug('installing luarocks: package=%s' % (package))
        if not run_command(['make', 'install'], verbose):
            logger.error('unable to install luarocks, exiting: package=%s' % (package))
            return False

    luarocks_config_file = path.join(environment_directory, 'etc', 'luarocks', 'config-5.1.lua')
    logger.debug('creating luarocks configuration file: file=%s' % (luarocks_config_file))

    include_path = '-I' + path.join(environment_directory, 'include')
    lib_path     = '-L' + path.join(environment_directory, 'lib')
    luarocks_config = """
rocks_trees = {
   { name = "user", root = home .. "/.luarocks" };
   { name = "system", root = "%s" };
}
lua_interpreter = "luajit";
variables = {
   LUA_DIR = "%s/openresty/luajit";
   LUA_INCDIR = "%s/openresty/luajit/include/luajit-2.1";
   LUA_BINDIR = "%s/openresty/luajit/bin";
   CFLAGS = "-O2 -fPIC %s";
   LIBFLAG = "-shared %s";
   OPENSSL_DIR = "%s";
   CRYPTO_DIR = "%s";
   YAML_DIR = "%s";
}
""" % (environment_directory, environment_directory, environment_directory, environment_directory,
       include_path, lib_path, environment_directory, environment_directory, environment_directory)
    with open(luarocks_config_file,"w+") as f:
        f.write(luarocks_config)

    return True

def download_and_extract_libyaml(environment_directory, tmp_directory, config, verbose):
    package = package_name('yaml', config['version'])
    tarball = tarball_name('yaml', config['version'])

    with cd(tmp_directory):
        tarball_url = LIBYAML_HOSTPATH + tarball
        logger.debug('fetching libyaml tarball: url=%s directory=%s' % (tarball_url, tmp_directory))
        if not run_command(['wget', '-q', tarball_url], verbose):
            logger.error('wget failed, exiting: url=%s directory=%s' % (tarball_url, tmp_directory))
            return False

        logger.debug('validating tarball hash: tarball=%s' % (tarball))
        libyaml_tarball_file = path.join(tmp_directory, tarball)
        if not validate_hash(libyaml_tarball_file, config['sha1']): 
            logger.error('tarball hash doesn\'t match, exiting')
            return False

        logger.debug('extracting tarball: tarball=%s directory=%s', tarball, tmp_directory)
        if not run_command(['tar', '-xf', libyaml_tarball_file], verbose):
            logger.error('unable to extract tarball, exiting: tarball=%s' % (libyaml_tarball_file))
            return False

    with cd(path.join(tmp_directory, package)):
        logger.debug('configuring libyaml package: package=%s' % (package))
        shell_command = ['./configure', '--prefix=' + environment_directory]
        if not run_command(['sh', '-c', ' '.join(shell_command)], verbose):
            logger.error('unable to configure libyaml package, exiting: package=%s' % (package))
            return False
 
        logger.debug('compiling libyaml package: package=%s' % (package))
        if not run_command(['make'], verbose):
            logger.error('unable to build libyaml, exiting: package=%s' % (package))
            return False

        logger.debug('installing libyaml packageL package=%s' % (package))
        if not run_command(['make', 'install'], verbose):
            logger.error('unable to install libyaml, exiting: package=%s' % (package))
            return False

    return True

def install_kong_luarock(environment_directory, config, verbose):
    luarocks_bin = path.join(environment_directory, 'bin', 'luarocks')

    # The build system for lyaml, this custom system called luke, for which lyaml
    # uses a bleeding edge, minified version of, doesn't find libyaml correctly. If you
    # follow its advice and specify YAML_DIR, it effectively ignores that. In order
    # to get it to find libyaml correctly, I need to force the appropriate of -L and -I
    # directives into the mercifully overridable C and LIB flags, so that it looks
    # for the locally built version of the library. We also need to specify OPENSSL_DIR
    # and CRYPTO_DIR so we pick up our locally build openssl library in all the right
    # places - styree
    include_path = '-I' + path.join(environment_directory, 'include')
    lib_path     = '-L' + path.join(environment_directory, 'lib')
    command = [luarocks_bin, 'install', '--tree', environment_directory, 'kong', config['version'],
               'CFLAGS=-O2 -fPIC %s %s' % (include_path, lib_path)]
    logger.debug('luarocks installing kong community: version=%s' % (config['version']))
    if not run_command(command, verbose):
        logger.error('unable to luarocks install kong community, exiting: version=%s' % (config['version']))
        return False

    return True

def create_activation_scripts(environment_directory, kong_version, lua_version, luajit_package):
    activation_script = """
if [[ "${KONG_ENV_ACTIVE}" == "%s" ]]; then
  echo 'error: requested kong-env is already activated, not activating again'
  return
elif [[ -n "${KONG_ENV_ACTIVE}" ]]; then
  echo "error: another kong-env (${KONG_ENV_ACTIVE}) currently activated, can not activate"
  return
fi

export KONG_ENV_ACTIVE="%s"
export OLD_PATH="$PATH"
export OLD_LD_LIBRARY_PATH="$LD_LIBRARY_PATH"
export OLD_LUA_PATH="$LUA_PATH"
export OLD_PS1="$PS1"
""" % (kong_version, kong_version)

    bin_directory           = path.join(environment_directory, 'bin')
    openresty_bin_directory = path.join(environment_directory, 'openresty', 'bin')
    luajit_bin_directory    = path.join(environment_directory, 'openresty', 'luajit', 'bin')
    nginx_bin_directory     = path.join(environment_directory, 'openresty', 'nginx' , 'sbin')
    activation_script += 'export PATH=%s:%s:%s:%s:$PATH\n' % (luajit_bin_directory, openresty_bin_directory,
                                                              bin_directory, nginx_bin_directory)

    openresty_luajit_include      = path.join(environment_directory, 'openresty', 'luajit', 'share', luajit_package, '?.lua')
    openresty_luajit_init_include = path.join(environment_directory, 'openresty', 'luajit', 'share', luajit_package, '?', 'init.lua')
    openresty_lua_include      = path.join(environment_directory, 'openresty', 'luajit', 'share', 'lua',
                                           lua_version[0:3], '?.lua')
    openresty_lua_init_include = path.join(environment_directory, 'openresty', 'luajit', 'share', 'lua',
                                           lua_version[0:3], '?', 'init.lua')
    lua_include      = path.join(environment_directory, 'share', 'lua', lua_version[0:3], '?.lua')
    lua_init_include = path.join(environment_directory, 'share', 'lua', lua_version[0:3], '?', 'init.lua')

    activation_script += 'export LUA_PATH="%s;%s;%s;%s;%s;%s"\n' % (openresty_luajit_include, openresty_luajit_init_include,
                                                                    openresty_lua_include, openresty_lua_init_include,
                                                                    lua_include, lua_init_include)
    activation_script += 'alias luarocks=\'luarocks --tree %s\'\n' % (environment_directory)

    ps1_prefix = '(kong-%s)' % (kong_version)
    activation_script += 'export PS1="%s $PS1"\n' % (ps1_prefix)

    lib_directory        = path.join(environment_directory, 'lib')
    luajit_lib_directory = path.join(environment_directory, 'openresty', 'luajit', 'lib', 'lua', lua_version[0:3])
    activation_script += 'export LD_LIBRARY_PATH=%s:%s:$LD_LIBRARY_PATH\n' % (lib_directory, luajit_lib_directory)

    with open(path.join(bin_directory, 'activate'), "w") as activate_file:
        activate_file.write(activation_script)

    deactivation_script = """
if [[ "${KONG_ENV_ACTIVE}" != "%s" ]]; then
  echo 'error: specified kong-env (%s) not currently activated, so it can not be deactivated'
  return
fi

[ `alias | grep luarocks | wc -l` != 0 ] && unalias luarocks
unset KONG_ENV_ACTIVE

export PATH="$OLD_PATH"
export LD_LIBRARY_PATH="$OLD_LD_LIBRARY_PATH"
export LUA_PATH="$OLD_LUA_PATH"
export PS1="$OLD_PS1"
""" % (kong_version, kong_version)
    with open(path.join(bin_directory, 'deactivate'), "w") as deactivate_file:
        deactivate_file.write(deactivation_script)

    return True

def cleanup_directory(directory, verbose):
    return run_command(['rm', '-rf', directory], verbose)

def initialize(environment_directory, kong_config, kong_version, verbose):
    logger.info('[1/11] creating environment directory: directory=%s' % (environment_directory))
    if not create_directory(environment_directory):
        logger.error('unable to create environment, exiting: directory=%s' % (environment_directory))
        sys.exit(1)

    tmp_directory = path.join(environment_directory, 'tmp')
    logger.info('[2/11] creating temporary directory: directory=%s' % (tmp_directory))
    if not create_directory(tmp_directory):
        logger.error('unable to create temporary directory, exiting: directory=%s' % (tmp_directory))
        sys.exit(1)

    openssl_config = kong_config['openssl']
    logger.info('[3/11] downloading, compiling and installing openssl: version=%s' % (openssl_config['version']))
    if not download_and_extract_openssl(environment_directory, tmp_directory, openssl_config, verbose):
        sys.exit(1)

    pcre_config = kong_config['pcre']
    logger.info('[4/11] downloading pcre: version=%s' % (pcre_config['version']))
    if not download_and_extract_pcre(environment_directory, tmp_directory, pcre_config, verbose):
        sys.exit(1)

    lua_kong_nginx_module_config = None
    if 'lua-kong-nginx-module' not in kong_config:
        logger.info('[5/11] skipping downloading lua-kong-nginx-module')
    else:
        lua_kong_nginx_module_config = kong_config['lua-kong-nginx-module']
        logger.info('[5/11] downloading lua-kong-nginx-module: version=%s' % (lua_kong_nginx_module_config['version']))
        if not download_lua_kong_nginx_module(environment_directory, tmp_directory, lua_kong_nginx_module_config, verbose):
            sys.exit(1)

    openresty_config = kong_config['openresty']
    logger.info('[6/11] downloading, compiling and installing openresty: version=%s' % (openresty_config['version']))
    pcre_package = package_name('pcre', pcre_config['version'])
    if not download_and_extract_openresty(environment_directory, tmp_directory, openresty_config, pcre_package, lua_kong_nginx_module_config, verbose):
        sys.exit(1)

    luarocks_config = kong_config['luarocks']
    logger.info('[7/11] downloading and installing luarocks: version=%s' % (luarocks_config['version']))
    if not download_and_extract_luarocks(environment_directory, tmp_directory, luarocks_config,
                                         openresty_config['lua_version'], openresty_config['luajit_version'],
                                         verbose):
        sys.exit(1)

    libyaml_config = kong_config['libyaml']
    logger.info('[8/11] downloading, compiling and installing libyaml: version=%s' % (libyaml_config['version']))
    if not download_and_extract_libyaml(environment_directory, tmp_directory, libyaml_config, verbose):
        sys.exit(1)

    kong_community_config = kong_config['kong-community']
    logger.info('[9/11] installing kong community luarock: version=%s' % (kong_community_config['version']))
    if not install_kong_luarock(environment_directory, kong_community_config, verbose):
        sys.exit(1)

    logger.info('[10/11] creating activation scripts')
    if not create_activation_scripts(environment_directory, kong_version, openresty_config['lua_version'], openresty_config['luajit_package']):
        sys.exit(1)

    logger.info('[11/11] cleaning up temp directory')
    if not cleanup_directory(tmp_directory, verbose):
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Initializes a local Kong development environment')
    parser.add_argument('--version', '-v', required=True, help='The Kong Enterprise Edition version')
    parser.add_argument('--environment', '-e', help='(Optional) The name of the environment (default is kong-<version>)')
    parser.add_argument('--dump-info', '-d', help='(Optional) Dump out configuration info for the specified version', action='store_true')
    parser.add_argument('--verbose', help='Optional: Specifies verbose logger', action='store_true')
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if args.version not in CONFIG:
        logger.error('Specified Kong Enterprise version (%s) not supported, exiting' % (args.version))
        sys.exit(1)
    kong_config = CONFIG[args.version]

    if args.dump_info:
        print(json.dumps(kong_config, indent=4, sort_keys=True))
        sys.exit(0)

    environment_name = 'kong-' + args.version
    if args.environment is not None:
        if args.environment == '..' or args.environment.find('/') != -1:
            logger.error('invalid or unsafe environment name (%s), exiting' % (args.environment))
            sys.exit(1)
        environment_name = args.environment

    environment_directory = path.abspath(path.join('.', environment_name))
    if path.isdir(environment_directory):
        logger.error('kong environment (%s) already exists. exiting' % (environment_name))
        sys.exit(1)

    logger.info('initializing self-contained kong enterprise development environment: version=%s' % (args.version))
    initialize(environment_directory, kong_config, args.version, args.verbose)
    logger.info('done')

if __name__ == "__main__":
    main()
