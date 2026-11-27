# SigmaOS-jails

**SigmaOS Jails — lightweight process, filesystem, and capability isolation**

Part of [SigmaOS](https://github.com/AaryanSinghChauhan09/Sigma).

## Features
- Isolated rootfs jail definitions with read-only or writable mount policies
- Least-privilege capability sets and network isolation modes (`None`, `LoopbackOnly`, `Bridged`)
- Deterministic resource limits (memory cap, PID cap, CPU shares)
- Lifecycle state machine (`Stopped` → `Running` → `Stopped`) with validation

## Usage
```bash
sigma-jail --help
```

## Documentation
- [SigmaOS Wiki](https://github.com/AaryanSinghChauhan09/sigmaos-wiki-staging/blob/master/SigmaOS-jails.md)

## See Also

Related SigmaOS **security** repositories:

- [SigmaOS-recovery-system](../SigmaOS-recovery-system/README.md) — SigmaOS snapshot & recovery manager
- [SigmaOS-rollback](../SigmaOS-rollback/README.md) — SigmaOS atomic transaction rollback
- [SigmaOS-zfs-integration](../SigmaOS-zfs-integration/README.md) — SigmaOS ZFS dataset & snapshot integration
- [SigmaOS-pkg-core](../SigmaOS-pkg-core/README.md) — SigmaOS core package manager

## License
GPL-3.0-or-later
