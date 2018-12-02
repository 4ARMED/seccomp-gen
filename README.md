# seccomp-gen

> Docker Secure Computing Profile Generator

---

## Why 🤔

This tool allows you to pipe the output of [strace](https://strace.io) through it and it will auto-generate a docker seccomp profile that can be used to only whitelist the syscalls you container needs to run and blacklists everything else.

This adds a LOT of security by drastically limiting your attack surface to only what is needed.

## Install

### macOS

```bash
$ brew install blacktop/tap/seccomp-gen
```

### linux/windows

Download from [releases](https://github.com/blacktop/seccomp-gen/releases/latest)

## Getting Started

```bash
$ strace -ff curl github.com 2>&1 | scgen --verbose

   • found syscall: execve
   • found syscall: brk
   • found syscall: access
   • found syscall: access
   • found syscall: openat
   • found syscall: fstat
   • found syscall: mmap
   ...
```

```bash
$ ls -lah

drwxr-xr-x   4 blacktop  staff   128B Dec  1 20:24 seccomp
```

### Inside Docker

Create a new Dockerfile

```dockerfile
FROM <your>/<image>:<tag>
RUN apt-get update && apt-get install -y strace
CMD ["strace","-ff","/your-entrypoint.sh"]
```

Build `scgen` image

```bash
$ docker build -t <your>/<image>:scgen .
```

Generate `seccomp` profile from docker logs output

```bash
docker run --rm --security-opt seccomp=unconfined <your>/<image>:scgen 2>&1 | scgen --verbose
```

## Credits

- https://blog.jessfraz.com/post/how-to-use-new-docker-seccomp-profiles/
- https://github.com/antitree/syscall2seccomp

## TODO

- [ ] filter strace through linux (32|64bit) [tbl](https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl) files like Jess does
- [ ] add support for consuming sysdig output
- [ ] only add current arch to arches

## Issues

Find a bug? Want more features? Find something missing in the documentation? Let me know! Please don't hesitate to [file an issue](https://github.com/blacktop/seccomp-gen/issues/new)

## License

MIT Copyright (c) 2018 **blacktop**
