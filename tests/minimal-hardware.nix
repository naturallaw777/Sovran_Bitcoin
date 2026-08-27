# Minimal hardware profile so plain `nixosSystem` evaluation passes the
# bootability assertions. The `.vm` build (qemu-vm.nix) layers its own
# QEMU machinery on top of this.
{ ... }:

{
  fileSystems."/" = {
    device = "tmpfs";
    fsType = "tmpfs";
  };
  boot.loader.grub.devices = [ "nodev" ];
}
