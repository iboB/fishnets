# fishnets

A client/server library for HTTP and WebSocket communication.

This is a thin(-ish) wrapper of Boost.Asio and Boost.Beast. The main reason for its existence it to have something which can abstract away the incredibly heavy compilation toll these libraries impose on the user. This way you compile asio/beast once and link against fishnets, which is orders of magnitude faster to compile.

## Copying

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)

This software is distributed under the MIT Software License.

See accompanying file LICENSE or copy [here](https://opensource.org/licenses/MIT).

Copyright &copy; 2021-2025 [Borislav Stanimirov](http://github.com/iboB)
