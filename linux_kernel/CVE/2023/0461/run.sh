qemu-system-x86_64 \
    -enable-kvm \
    -cpu qemu64,+smep,+smap,+rdrand \
    -smp 2 \
    -m 4G \
    -kernel ./non-kasan/bzImage \
    -initrd ./rootfs.cpio.gz \
    -append "console=ttyS0 kgdbwait kgdboc=ttyS1,115200 oops=panic panic=-1 pti=on quiet kaslr" \
    -netdev user,id=mynet0 \
    -device virtio-net-pci,netdev=mynet0 \
    -pidfile vm.pid \
    -gdb tcp:localhost:1234 \
    -nographic \
    -no-reboot \
#    -S
