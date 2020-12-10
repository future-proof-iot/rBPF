<a href="https://riot-os.org/">
  <img alt="RIOT" src="https://raw.githubusercontent.com/RIOT-OS/RIOT/master/doc/doxygen/src/riot-logo.svg" width="400">
</a>

[![Nightly CI status master][master-ci-badge]][master-ci-link]
[![GitHub release][release-badge]][release-link]
[![License][license-badge]][license-link]
[![API docs][api-badge]][api-link]
[![Wiki][wiki-badge]][wiki-link]
[![Stack Overflow questions][stackoverflow-badge]][stackoverflow-link]
[![Twitter][twitter-badge]][twitter-link]
[![IRC][irc-badge]][irc-link]
[![Matrix][matrix-badge]][matrix-link]

The friendly Operating System for IoT! **rBPF fork!**

RIOT is a real-time multi-threading operating system that supports a range of
devices that are typically found in the Internet of Things (IoT):
8-bit, 16-bit and 32-bit microcontrollers.

RIOT is based on the following design principles: energy-efficiency, real-time
capabilities, small memory footprint, modularity, and uniform API access,
independent of the underlying hardware (this API offers partial POSIX
compliance).

RIOT is developed by an international open source community which is
independent of specific vendors (e.g. similarly to the Linux community).
RIOT is licensed with LGPLv2.1, a copyleft license which fosters
indirect business models around the free open-source software platform
provided by RIOT, e.g. it is possible to link closed-source code with the
LGPL code.

## FEATURES

This fork contains the rBPF code and application as integrated with RIOT.


## GETTING STARTED

Assuming you want to get started with the rBPF, the recommended approach is to start with the [gcoap_bpf example](examples/gcoap_bpf).

## Required tooling

- GCC, and the specific flavour required for the platform.
- LLVM/Clang for creating BPF binaries


[api-badge]: https://img.shields.io/badge/docs-API-informational.svg
[api-link]: https://riot-os.org/api/
[irc-badge]: https://img.shields.io/badge/chat-IRC-brightgreen.svg
[irc-link]: https://webchat.freenode.net?channels=%23riot-os
[license-badge]: https://img.shields.io/github/license/RIOT-OS/RIOT
[license-link]: https://github.com/RIOT-OS/RIOT/blob/master/LICENSE
[master-ci-badge]: https://ci.riot-os.org/RIOT-OS/RIOT/master/latest/badge.svg
[master-ci-link]: https://ci.riot-os.org/nightlies.html#master
[matrix-badge]: https://img.shields.io/badge/chat-Matrix-brightgreen.svg
[matrix-link]: https://matrix.to/#/#riot-os:matrix.org
[release-badge]: https://img.shields.io/github/release/RIOT-OS/RIOT.svg
[release-link]: https://github.com/RIOT-OS/RIOT/releases/latest
[stackoverflow-badge]: https://img.shields.io/badge/stackoverflow-%5Briot--os%5D-yellow
[stackoverflow-link]: https://stackoverflow.com/questions/tagged/riot-os
[twitter-badge]: https://img.shields.io/badge/social-Twitter-informational.svg
[twitter-link]: https://twitter.com/RIOT_OS
[wiki-badge]: https://img.shields.io/badge/docs-Wiki-informational.svg
[wiki-link]: https://github.com/RIOT-OS/RIOT/wiki
