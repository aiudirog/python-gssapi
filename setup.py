#!/usr/bin/env python
from __future__ import print_function

from setuptools import setup
from setuptools import Distribution
from setuptools.command.sdist import sdist
from setuptools.extension import Extension
import math
import subprocess
import platform
import re
import sys
import os
import shutil
import shlex


ARCH = int(math.log(sys.maxsize, 2)) + 1  # 64 or 32

SKIP_CYTHON_FILE = '__dont_use_cython__.txt'

if os.path.exists(SKIP_CYTHON_FILE):
    print("In distributed package, building from C files...", file=sys.stderr)
    SOURCE_EXT = 'c'
else:
    try:
        from Cython.Build import cythonize
        print("Building from Cython files...", file=sys.stderr)
        SOURCE_EXT = 'pyx'
    except ImportError:
        print("Cython not found, building from C files...", file=sys.stderr)
        SOURCE_EXT = 'c'


def get_output(*args, **kwargs):
    res = subprocess.check_output(*args, shell=True, **kwargs)
    decoded = res.decode('utf-8')
    return decoded.strip()


class Config:
    def __init__(self):
        def shsplit(value):
            return value if isinstance(value, list) else shlex.split(value)

        link_args = shsplit(
            os.environ.get('GSSAPI_LINKER_ARGS')
            or self._default_link_args
        )
        # Separate out specific types of link args to pass separately to
        # Extension. This helps specific library dirs come before generic ones
        # and allows the usage of other compilers with different cli arg styles
        self.library_dirs, self.libraries, self.link_args = [], [], []
        for arg in link_args:
            if arg.startswith('-L'):
                self.library_dirs.append(arg[2:])
            elif arg.startswith('-l'):
                self.libraries.append(arg[2:])
            else:
                self.link_args.append(arg)

        self.compile_args = shsplit(
            os.environ.get('GSSAPI_COMPILER_ARGS')
            or self._default_compile_args
        )

        # add in the extra workarounds for different include structures
        ext_h = os.path.join(self._prefix, 'include/gssapi/gssapi_ext.h')
        if os.path.exists(ext_h):
            self.compile_args.append("-DHAS_GSSAPI_EXT_H")

        self.enable_support_detect = \
            os.environ.get('GSSAPI_SUPPORT_DETECT', 'true').lower() == 'true'

        if self.enable_support_detect:
            try:
                main_lib = os.environ['GSSAPI_MAIN_LIB']
            except KeyError:
                main_lib = self._gssapi_lib_path
            if main_lib is None:
                raise Exception(
                    "Could not find main GSSAPI shared library. Please "
                    "try setting GSSAPI_MAIN_LIB yourself or "
                    "setting ENABLE_SUPPORT_DETECTION to 'false'"
                )
            import ctypes
            self.gssapi_lib = ctypes.CDLL(main_lib)
        else:
            self.gssapi_lib = None

    @property
    def _default_link_args(self):
        """String or list of strings of default linker args."""
        return get_output('krb5-config --libs gssapi')

    @property
    def _default_compile_args(self):
        """String or list of strings of default compiler args."""
        return get_output('krb5-config --cflags gssapi')

    @property
    def _prefix(self):
        """Path to KRB5 prefix."""
        try:
            return get_output('krb5-config gssapi --prefix')
        except Exception:
            print("WARNING: couldn't find krb5-config; assuming prefix of %s"
                  % str(sys.prefix))
            return sys.prefix

    @property
    def _gssapi_lib_path(self):
        """Path to libgssapi.so or gssapi.dll depending on the system."""
        # To support Heimdal on Debian, read the linker path.
        main_path = next(
            (o[4:] for o in self.link_args if o.startswith('-Wl,/')), ''
        )
        for opt in self.libraries:
            if opt.startswith('gssapi'):
                return os.path.join(main_path, 'lib%s.so' % opt)

    def make_extension(self, name_fmt, module, **kwargs):
        """Create extension for the given module using the current config."""
        source = name_fmt.replace('.', '/') % module + '.' + SOURCE_EXT
        if not os.path.exists(source):
            raise OSError(source)
        return Extension(
            name_fmt % module,
            extra_link_args=self.link_args,
            extra_compile_args=self.compile_args,
            library_dirs=self.library_dirs,
            libraries=self.libraries,
            sources=[source],
            **kwargs
        )


class DarwinGSSFrameWorkConfig(Config):
    _default_link_args = ['-framework', 'GSS']
    _default_compile_args = _default_link_args + ['-DOSX_HAS_GSS_FRAMEWORK']

    @property
    def _gssapi_lib_path(self):
        import ctypes.util
        return ctypes.util.find_library('GSS')


class WindowsConfig(Config):
    def __init__(self):
        self._krb_path = self._find_krb()
        self._patch_cygwincc()
        super().__init__()

    @property
    def _default_link_args(self):
        libs = os.path.join(
            self._krb_path, 'lib', 'amd64' if ARCH == 64 else 'i386'
        )
        return (
            ['-L%s' % libs]
            + ['-l%s' % os.path.splitext(lib)[0] for lib in os.listdir(libs)]
        )

    @property
    def _default_compile_args(self):
        return ['-I%s' % os.path.join(self._krb_path, 'include'), '-DMS_WIN64']

    @property
    def _prefix(self):
        return self._krb_path

    @property
    def _gssapi_lib_path(self):
        for opt in self.libraries:
            if opt.startswith('gssapi'):
                return os.path.join(self._krb_path, 'bin', '%s.dll' % opt)

    @staticmethod
    def _find_krb():
        """Try to find location of MIT kerberos."""
        # First check program files of the appropriate architecture
        pf_path = os.path.join(os.environ['ProgramFiles'], 'MIT', 'Kerberos')
        if os.path.exists(pf_path):
            return pf_path
        # Try to detect kinit in PATH
        kinit_path = shutil.which('kinit')
        if kinit_path is None:
            raise OSError("Failed find MIT kerberos!")
        return os.path.dirname(os.path.dirname(kinit_path))

    @staticmethod
    def _patch_cygwincc():
        """
        Monkey patch distutils if it throws errors getting msvcr.
        MinGW doesn't need it anyway.
        """
        from distutils import cygwinccompiler
        try:
            cygwinccompiler.get_msvcr()
        except ValueError:
            cygwinccompiler.get_msvcr = lambda *a, **kw: []


class MSYSConfig(Config):
    def __init__(self):
        super().__init__()
        # Create a define to detect msys in the headers
        self.compile_args.append('-D__MSYS__')

    if os.environ.get('MINGW_PREFIX'):
        _default_link_args = ['-lgss']
        _default_compile_args = ['-fPIC']
        _gssapi_lib_path = os.environ.get('MINGW_PREFIX') + '/bin/libgss-3.dll'
    else:
        @property
        def _gssapi_lib_path(self):
            # Plain msys, not running in MINGW_PREFIX.
            # Try to get the lib from one of them.
            main_lib = '/mingw%d/bin/libgss-3.dll' % ARCH
            if os.path.exists(main_lib):
                os.environ['PATH'] += os.pathsep + os.path.dirname(main_lib)
                return main_lib


# Choose the right config for the current platform.
if os.name == 'nt':
    config = WindowsConfig()
elif (sys.platform == 'darwin'
        and [int(v) for v in platform.mac_ver()[0].split('.')] >= [10, 7, 0]):
    config = DarwinGSSFrameWorkConfig()
elif sys.platform == 'msys':
    config = MSYSConfig()
else:
    config = Config()


# add in the flag that causes us not to compile from Cython when
# installing from an sdist
class sdist_gssapi(sdist):
    def run(self):
        if not self.dry_run:
            with open(SKIP_CYTHON_FILE, 'w') as flag_file:
                flag_file.write('COMPILE_FROM_C_ONLY')

            sdist.run(self)

            os.remove(SKIP_CYTHON_FILE)


DONT_CYTHONIZE_FOR = ('clean',)


class GSSAPIDistribution(Distribution, object):
    def run_command(self, command):
        self._last_run_command = command
        Distribution.run_command(self, command)

    @property
    def ext_modules(self):
        if SOURCE_EXT != 'pyx':
            return getattr(self, '_ext_modules', None)

        if getattr(self, '_ext_modules', None) is None:
            return None

        if getattr(self, '_last_run_command', None) in DONT_CYTHONIZE_FOR:
            return self._ext_modules

        if getattr(self, '_cythonized_ext_modules', None) is None:
            self._cythonized_ext_modules = cythonize(
                self._ext_modules,
                language_level=2,
            )

        return self._cythonized_ext_modules

    @ext_modules.setter
    def ext_modules(self, mods):
        self._cythonized_ext_modules = None
        self._ext_modules = mods

    @ext_modules.deleter
    def ext_modules(self):
        del self._ext_modules
        del self._cythonized_ext_modules


# detect support
def main_file(module):
    return config.make_extension('gssapi.raw.%s', module)


ENUM_EXTS = []


def extension_file(module, canary):
    if config.enable_support_detect and not hasattr(config.gssapi_lib, canary):
        print('Skipping the %s extension because it '
              'is not supported by your GSSAPI implementation...' % module)
        return

    try:
        ENUM_EXTS.append(
            config.make_extension(
                'gssapi.raw._enum_extensions.ext_%s', module,
                include_dirs=['gssapi/raw/']
            )
        )
    except OSError:
        pass

    return config.make_extension('gssapi.raw.ext_%s', module)


def gssapi_modules(lst):
    # filter out missing files
    res = [mod for mod in lst if mod is not None]

    # add in supported mech files
    res.extend(
        config.make_extension('gssapi.raw.mech_%s', mech)
        for mech in os.environ.get('GSSAPI_MECHS', 'krb5').split(',')
    )

    # add in any present enum extension files
    res.extend(ENUM_EXTS)

    return res


long_desc = re.sub(r'\.\. role:: \w+\(code\)\s*\n\s*.+', '',
                   re.sub(r':(python|bash|code):', '',
                          re.sub(r'\.\. code-block:: \w+', '::',
                                 open('README.txt').read())))

install_requires = [
    'decorator',
    'six >= 1.4.0'
]
if sys.version_info < (3, 4):
    install_requires.append('enum34')

setup(
    name='gssapi',
    version='1.5.1',
    author='The Python GSSAPI Team',
    author_email='sross@redhat.com',
    packages=['gssapi', 'gssapi.raw', 'gssapi.raw._enum_extensions',
              'gssapi.tests'],
    description='Python GSSAPI Wrapper',
    long_description=long_desc,
    license='LICENSE.txt',
    url="https://github.com/pythongssapi/python-gssapi",
    classifiers=[
        'Development Status :: 4 - Beta',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: ISC License (ISCL)',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Cython',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    distclass=GSSAPIDistribution,
    cmdclass={'sdist': sdist_gssapi},
    ext_modules=gssapi_modules([
        main_file('misc'),
        main_file('exceptions'),
        main_file('creds'),
        main_file('names'),
        main_file('sec_contexts'),
        main_file('types'),
        main_file('message'),
        main_file('oids'),
        main_file('cython_converters'),
        main_file('chan_bindings'),
        extension_file('s4u', 'gss_acquire_cred_impersonate_name'),
        extension_file('cred_store', 'gss_store_cred_into'),
        extension_file('rfc5587', 'gss_indicate_mechs_by_attrs'),
        extension_file('rfc5588', 'gss_store_cred'),
        extension_file('rfc5801', 'gss_inquire_saslname_for_mech'),
        extension_file('cred_imp_exp', 'gss_import_cred'),
        extension_file('dce', 'gss_wrap_iov'),
        extension_file('iov_mic', 'gss_get_mic_iov'),
        extension_file('ggf', 'gss_inquire_sec_context_by_oid'),
        extension_file('set_cred_opt', 'gss_set_cred_option'),

        # see ext_rfc6680_comp_oid for more information on this split
        extension_file('rfc6680', 'gss_display_name_ext'),
        extension_file('rfc6680_comp_oid', 'GSS_C_NT_COMPOSITE_EXPORT'),

        # see ext_password{,_add}.pyx for more information on this split
        extension_file('password', 'gss_acquire_cred_with_password'),
        extension_file('password_add', 'gss_add_cred_with_password'),
    ]),
    keywords=['gssapi', 'security'],
    install_requires=install_requires
)
