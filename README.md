<!---
 Copyright (C) 2018 Jiajie Chen
 
 This file is part of gretapmac.
 
 gretapmac is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 
 gretapmac is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License
 along with gretapmac.  If not, see <http://www.gnu.org/licenses/>.
 
-->

gretapmac
================================

A GRETAP implementation for macOS. Requires [tuntaposx](http://tuntaposx.sourceforge.net/). Tunnelblick also provides a signed version of it.


Usage
================================

```shell
$ mkdir build
$ cd build
$ cmake ..
$ make
$ ./gretapmac # Usage help
Usage: gretapmac [tap_if] [local_ip] [remote_ip]
    equivalent to: ip link add [tap_if] type gretap local [local_ip] remote [remote_ip]
$ sudo ./gretapmac tap0 192.168.0.1 1.2.3.4
```