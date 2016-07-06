# ngx_upstream_resolveMK

An nginx upstream resolve module using DNS SRV record based on ngx_upstream_jdomain.
Works nicely with Mesos-DNS.

Installation:

```
	./configure --add-module=/path/to/this/directory
	make
	make install
```

Usage:

```
	upstream backend {
		resolveMK marathon.mesos service=_rails._tcp
	}
```

resolveMK:

```
  * Syntax: resolveMK <domain-name> <service=service_name> [max_ip=20] [interval=10s] [retry_off]
  * Context: upstream
  * service: service name
  * max_ip: IP buffer size.
  * interval: DNS cache refresh interval.
  * retry_off: Do not retry if one IP fails.
```

# Special Thanks

wdaike <wdaike@163.com>, Baidu Inc, an author of ngx_upstream_jdomain.

# Copyright & License

This module is licenced under the BSD License.

Copyright (c) 2016, Kim SeungSu
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
