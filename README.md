# libQuotient (former libQMatrixClient)

<a href='https://matrix.org'><img src='https://matrix.org/docs/projects/images/made-for-matrix.png' alt='Made for Matrix' height=64 target=_blank /></a>

[![license](https://img.shields.io/github/license/quotient-im/libQuotient.svg)](https://github.com/quotient-im/libQuotient/blob/dev/COPYING)
![status](https://img.shields.io/badge/status-beta-yellow.svg)
[![release](https://img.shields.io/github/release/quotient-im/libQuotient/all.svg)](https://github.com/quotient-im/libQuotient/releases/latest)
[![](https://img.shields.io/cii/percentage/1023.svg?label=CII%20best%20practices)](https://bestpractices.coreinfrastructure.org/projects/1023/badge)
![](https://img.shields.io/github/commit-activity/y/quotient-im/libQuotient.svg)
![CI Status](https://img.shields.io/github/workflow/status/quotient-im/libQuotient/CI)
![Sonar Tech Debt](https://img.shields.io/sonar/tech_debt/quotient-im_libQuotient?server=https%3A%2F%2Fsonarcloud.io)
![Sonar Coverage](https://img.shields.io/sonar/coverage/quotient-im_libQuotient?server=https%3A%2F%2Fsonarcloud.io)
![Matrix](https://img.shields.io/matrix/quotient:matrix.org?logo=matrix)

The Quotient project aims to produce a Qt5-based SDK to develop applications
for [Matrix](https://matrix.org). libQuotient is a library that enables client
applications. It is the backbone of
[Quaternion](https://github.com/quotient-im/Quaternion),
[NeoChat](https://matrix.org/docs/projects/client/neo-chat) and other projects.
Versions 0.5.x and older use the previous name - libQMatrixClient.

## Contacts
You can find Quotient developers in the Matrix room:
[#quotient:matrix.org](https://matrix.to/#/#quotient:matrix.org).

You can file issues at
[the project issue tracker](https://github.com/quotient-im/libQuotient/issues).
If you find what looks like a security issue, please use instructions
in SECURITY.md.

## Getting and using libQuotient
Depending on your platform, the library can be obtained from a package
management system. Recent releases of Fedora, Debian and openSUSE already have
it. Alternatively, you can build the library from the source and bundle it with
your application, as described below.

### Pre-requisites
To use libQuotient (i.e. build or run applications with it), you'll need:
- A recent Linux, macOS or Windows system (desktop versions are known to work;
  mobile operating systems where Qt is available might work too)
  - Recent enough Linux examples: Debian Bullseye; Fedora 35;
    openSUSE Leap 15.4; Ubuntu 22.04 LTS.
- Qt 5.15 or 6 (experimental, as of libQuotient 0.7) - either Open Source or
  Commercial
- Qt Keychain (https://github.com/frankosterfeld/qtkeychain) - 0.12 or newer is
  recommended, the build should match the Qt major version
  
To build applications with libQuotient, you'll also need:
- CMake 3.16 or newer
- A C++ toolchain that supports at least some subset of C++20 (concepts,
  in particular):
  - GCC 11 (Windows, Linux, macOS), Clang 11 (Linux), Apple Clang 12 (macOS)
    and Visual Studio 2019 (Windows) are the oldest officially supported.
- If using E2EE (beta, as of libQuotient 0.7):
  - libolm 3.2.5 or newer (the latest 3.x strongly recommended)
  - OpenSSL (1.1.x and 3.x are known to work).
- Any build system that works with CMake should be fine:
  GNU Make and ninja on any platform, NMake and jom on Windows are known to work.
  Ninja is recommended.
  
The requirements to build libQuotient itself are basically the same except
that you should install development libraries for the list above.


#### Linux
Just install the prerequisites using your preferred package manager. If your Qt
package base is fine-grained you might want to run CMake and look at error
messages. The library is entirely offscreen but aside from QtCore and QtNetwork;
it only depends on QtGui in order to handle avatar thumbnails.

#### macOS
`brew install qt qtkeychain` should get you the most recent versions of the
runtime libraries. You may need to add the output of `brew --prefix qt` and
`brew --prefix qtkeychain` to `CMAKE_PREFIX_PATH` (see below) to make CMake
aware of the library locations. There is no qtkeychain built with Qt 6 on
Homebrew; if you need to go with Qt 5, you have to build QtKeychain from
the source.

If using E2EE, you need to perform the same dance for libolm and openssl@1.1.
It is strongly recommended to have OpenSSL of the version that was used to build
Qt. As of this writing, it's 1.1.x; check https://formulae.brew.sh/formula/qt
for the most current situation

#### Windows
Install Qt using their official installer; make sure to tick the CMake box
in the list of installed components unless you already have it installed. This
will get you both the runtime libraries and the files necessary for building
libQuotient or with libQuotient. Alternatively, you can use vcpkg to install
both Qt and QtKeychain.

If you use Qt Creator it will find Qt and CMake automatically, as long as all
of these are installed with the official installer. If you don't use Qt Creator,
the commands in further sections imply that `cmake` is in your `PATH`, otherwise
you have to prepend those commands with actual paths.

It's a good idea to run the `qtenv2.bat` script that can be found in
`C:\Qt\<Qt version>\<toolchain>\bin` (assuming you installed Qt to `C:\Qt`) if
you're building from the command line. This script adds necessary paths to
`PATH`. You might not want to run that script on system startup but it's very
handy to setup the environment before building.
Alternatively you can add the Qt path to `CMAKE_PREFIX_PATH` and leave `PATH`
unchanged. This is also the recommended way if you use an IDE different from
Qt Creator.

Qt Keychain doesn't distribute prebuilt packages so unless you use vcpkg you
should build it from the source code.

If you're trying out E2EE, you will also need libolm and OpenSSL. Unfortunately,
neither project provides official binary libraries for Windows. libolm can
be compiled from the sources (available at
https://gitlab.matrix.org/matrix-org/olm) using the same toolchain (CMake+MSVC).
It's not recommended to compile OpenSSL yourself; instead, use vcpkg or one of
the "OpenSSL for Windows" links in the
[unofficial list on the project Wiki](https://wiki.openssl.org/index.php/Binaries).
Make sure to install the development libraries, not only the runtime.


## Using the library
If you're just starting a project using libQuotient from scratch, you can copy
`quotest/CMakeLists.txt` to your project and change `quotest` to your
project name. If you already have an existing CMakeLists.txt, you need to insert
a `find_package(Quotient REQUIRED)` line to an appropriate place in it (use
`find_package(Quotient)` if libQuotient is not a hard dependency for you) and
then add `Quotient` to your `target_link_libraries()` line.

Building with dynamic linkage is only tested on Linux at the moment and is
a recommended way of linking your application with libQuotient on this platform.
Static linkage is the default on Windows/macOS; feel free to experiment
with dynamic linking and submit PRs if you get reusable results.

As for the actual API usage, a (very basic) overview can be found at
[the respective wiki page](https://github.com/quotient-im/libQuotient/wiki/libQuotient-overview).
Beyond that, looking at [Quotest](quotest) - the test application that comes
with libQuotient - may help you with most common use cases such as sending
messages, uploading files, setting room state etc. For more extensive usage
feel free to check out (and copy, with appropriate attribution) the source code
of [Quaternion](https://github.com/quotient-im/Quaternion) (the reference client
for libQuotient) or [NeoChat](https://invent.kde.org/network/neochat).


## Building the library
On platforms other than Linux you will have to build libQuotient yourself
before usage - nobody packaged it so far (contributions welcome!). You may also
want to build the library on Linux if you are to use newer/unstable versions.

[The source code is at GitHub](https://github.com/quotient-im/libQuotient).
Checking out a certain commit or tag (rather than downloading the archive)
along with submodules is strongly recommended. If you want to hack on
the library as a part of another project (e.g. you are working on Quaternion
but need to do some changes to the library code), it makes sense
to make a recursive check out of that project (in this case, Quaternion)
and update the library submodule (also recursively) within the appropriate
branch. Be mindful of API compatibility restrictions: e.g., Quaternion 0.0.95
will not build with the `dev` branch of libQuotient.

Tags consisting of digits and periods represent released versions; tags ending
with `-betaN` or `-rcN` mark pre-releases. If/when packaging pre-releases,
it is advised to replace this dash with a tilde.

The following commands issued in the root directory of the project sources:
```shell script
mkdir build_dir
cd build_dir
cmake .. # [-D<cmake-variable>=<value>...], see below
cmake --build . --target all
```
will get you a compiled library in `build_dir` inside your project sources.
Static builds are tested on all supported platforms, building the library as
a shared object (aka dynamic library) is supported on Linux and macOS but is
untested on Windows.

Before proceeding, double-check that you have installed development libraries
for all prerequisites above. CMake will stop and tell you if something's missing.

The first CMake invocation above configures the build. You can pass CMake
variables (such as `-DCMAKE_PREFIX_PATH="path1;path2;..."` and
`-DCMAKE_INSTALL_PREFIX=path`) here if needed.
[CMake documentation](https://cmake.org/cmake/help/latest/index.html)
(pick the CMake version at the top of the page that you use) describes
the standard variables coming with CMake. On top of them, Quotient introduces:
- `Quotient_INSTALL_TESTS=<ON/OFF>`, `ON` by default - install `quotest` along
  with the library files when `install` target is invoked. `quotest` is a small
  command-line program that (assuming correct parameters, see `quotest --help`)
  that tries to connect to a given room as a given user and perform some basic
  Matrix operations, such as sending messages and small files, redaction,
  setting room tags etc. This is useful to check the sanity of your library
  installation. As of now, `quotest` expects the used homeserver to be able
  to get the contents of `#quotient:matrix.org`; this is being fixed in
  [#401](https://github.com/quotient-im/libQuotient/issues/401).
- `Quotient_ENABLE_E2EE=<ON/OFF>`, `OFF` by default - enable work-in-progress
  E2EE code in the library. As of 0.6, this code is very incomplete and buggy;
  you should NEVER use it. In 0.7, the enabled code is beta-quality and is
  generally good for trying the technology but really not for mission-critical
  applications.

  Switching this on will define `Quotient_E2EE_ENABLED` macro (note
  the difference from the CMake switch) for compiler invocations on all
  Quotient and Quotient-dependent (if it uses `find_package(Quotient)`)
  code; so you can use `#ifdef Quotient_E2EE_ENABLED` to guard the code using
  E2EE parts of Quotient.
- `MATRIX_SPEC_PATH` and `GTAD_PATH` - these two variables are used to point
  CMake to the directory with the matrix-doc repository containing API files
  and to a GTAD binary. These two are used to generate C++ files from Matrix
  Client-Server API description made in OpenAPI notation. This is not needed
  if you just need to build the library; if you're really into hacking on it,
  CONTRIBUTING.md elaborates on what these two variables are for.

You can install the library with CMake:
```shell script
cmake --build . --target install
```
This will also install cmake package config files; once this is done, you
should be able to use [`quotest/CMakeLists.txt`](quotest/CMakeLists.txt) to compile quotest
with the _installed_ library. Installation of the `quotest` binary
along with the rest of the library can be skipped
by setting `Quotient_INSTALL_TESTS` to `OFF`.


## Troubleshooting

#### Building fails

- If `cmake` fails with
  ```
  CMake Warning at CMakeLists.txt:11 (find_package):
    By not providing "FindQt5Widgets.cmake" in CMAKE_MODULE_PATH this project
    has asked CMake to find a package configuration file provided by
    "Qt5Widgets", but CMake did not find one.
  ```
  then you need to set the right `-DCMAKE_PREFIX_PATH` variable, see above.
  
- If `cmake` fails with a message similar to:
  ```
  CMake Error at /usr/lib64/cmake/Qt6Core/Qt6CoreVersionlessTargets.cmake:37 (message):
    Some (but not all) targets in this export set were already defined.
  
    Targets Defined: Qt::Core
  
    Targets not yet defined: Qt::CorePrivate
  ```
  then you likely have both Qt 5 and Qt 6 on your system, and your client code
  uses a different major version than Quotient. Make sure you use the client
  version that matches libQuotient (e.g. you can't configure Quaternion 0.0.95
  with libQuotient 0.7 in Qt 6 mode).

- If you use GCC and get an "unknown declarator" compilation error in the file
`qtconcurrentthreadengine.h` - unfortunately, it is an actual error in Qt 5.15
sources, see https://bugreports.qt.io/browse/QTBUG-90568 (or
https://bugreports.qt.io/browse/QTBUG-91909). The Qt company did not make
an open source release with the fix, therefore:

  - if you're on Linux - try to use Qt from your package management system, as
    most likely this bug is already fixed in the packages
  - if you're on Windows, or if you have to use Qt (5.15) from download.qt.io
    for any other reason, you should apply the fix to Qt sources: locate
    the file (the GCC error message tells exactly where it is), find the line
    with the (strange-looking) `ThreadEngineStarter` constructor definition:
    ```cplusplus
    ThreadEngineStarter<void>(ThreadEngine<void> \*_threadEngine)
    ```
    and remove the template specialisation from the constructor name so that it
    looks like
    ```cplusplus
    ThreadEngineStarter(ThreadEngine<void> \*_threadEngine)
    ```
    This will fix your build (and any other build involving QtConcurrent from
    this installation of Qt - the fix is not specific to Quotient in any way).

#### Logging configuration

libQuotient uses Qt's logging categories to make switching certain types of logging easier. In case of troubles at runtime (bugs, crashes) you can increase logging if you add the following to the `QT_LOGGING_RULES` environment variable:
```
quotient.<category>.<level>=<flag>
```
where
- `<category>` is one of: `main`, `jobs`, `jobs.sync`, `jobs.thumbnail`,
  `events`, `events.state` (covering both the "usual" room state and account
  data), `events.messages`, `events.ephemeral`, `e2ee` and `profiler` (you can
  always find the full list in `lib/logging.cpp`);
- `<level>` is one of `debug`, `info`, and `warning`;
- `<flag>` is either `true` or `false`.

`*` can be used as a wildcard for any part between two dots, and semicolon is used for a separator. Latter statements override former ones, so if you want to switch on all debug logs except `jobs` you can set
```shell script
QT_LOGGING_RULES="quotient.*.debug=true;quotient.jobs.debug=false"
```
Note that `quotient` is a prefix that only works since version 0.6 of
the library; 0.5.x and older used `libqmatrixclient` instead. If you happen
to deal with both libQMatrixClient-era and Quotient-era versions,
it's reasonable to use both prefixes, to make sure you're covered with no
regard to the library version. For example, the above setting could look like
```shell script
QT_LOGGING_RULES="libqmatrixclient.*.debug=true;libqmatrixclient.jobs.debug=false;quotient.*.debug=true;quotient.jobs.debug=false"
```

#### Cache format
In case of troubles with room state and caching it may be useful to switch
cache format from binary to JSON. To do that, set the following value in
your client's configuration file/registry key (you might need to create
the libQuotient key for that): `libQuotient/cache_type` to `json`.
This will make cache saving and loading work slightly slower but the cache
will be in text JSON files (possibly very long and unindented so prepare a good
JSON viewer or text editor with JSON formatting capabilities).
