#!/bin/bash

ufw disable
cd bot

sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F
sudo iptables -t nat -X
sudo iptables -t mangle -F
sudo iptables -t mangle -X
sudo iptables -P INPUT ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo iptables -P FORWARD ACCEPT

service apache2 start
#INSTALL MEGA FOR CSKY CC
wget https://mega.nz/linux/repo/xUbuntu_20.04/amd64/megacmd-xUbuntu_20.04_amd64.deb
sudo apt install ./megacmd-xUbuntu_20.04_amd64.deb -y

mkdir -p /etc/xcompile
cd /etc/xcompile

# download compilers (replaced ubuntu's legacy ones with these i found)
mega-get 'https://mega.nz/file/LgBRXSRQ#OReuzxJlfJxXCsbbVbjm9-sizcAiIZSkZDy-Y7n59q8' # FOR cross-compiler-csky.tar.gz|folderOutput=csky-gcc
wget https://github.com/foss-for-synopsys-dwc-arc-processors/toolchain/releases/download/arc-2017.09-release/arc_gnu_2017.09_prebuilt_uclibc_le_arc700_linux_install.tar.gz
wget https://landley.net/aboriginal/downloads/binaries/cross-compiler-powerpc.tar.gz
wget https://landley.net/aboriginal/downloads/binaries/cross-compiler-sh4.tar.gz
wget https://landley.net/aboriginal/downloads/binaries/cross-compiler-mips.tar.gz
wget https://landley.net/aboriginal/downloads/binaries/cross-compiler-mipsel.tar.gz
wget https://landley.net/aboriginal/downloads/binaries/cross-compiler-x86_64.tar.gz
wget https://landley.net/aboriginal/downloads/binaries/cross-compiler-m68k.tar.gz
wget https://landley.net/aboriginal/downloads/binaries/cross-compiler-sparc.tar.gz
wget https://landley.net/aboriginal/downloads/binaries/cross-compiler-i486.tar.gz
wget https://landley.net/aboriginal/downloads/binaries/cross-compiler-armv4l.tar.gz
wget https://landley.net/aboriginal/downloads/binaries/cross-compiler-armv5l.tar.gz
wget https://landley.net/aboriginal/downloads/binaries/cross-compiler-armv6l.tar.gz
wget https://github.com/rawbypa/armv7l/raw/main/cross-compiler-armv7l.tar.bz2 -O cross-compiler-armv7l.tar.bz2
wget https://toolchains.bootlin.com/downloads/releases/toolchains/aarch64/tarballs/aarch64--uclibc--stable-2024.05-1.tar.xz -O aarch64-toolchain.tar.xz --waitretry=0 --tries=0 --timeout=3
wget https://occ-oss-prod.oss-cn-hangzhou.aliyuncs.com/resource/1356021/1619527806432/csky-linux-uclibc-tools-x86_64-uclibc-linux-4.9.56-20210423.tar.gz -O cross-compiler-csky.tar.gz

# extract compilers
# ARC
if [ -f arc_gnu_2017.09_prebuilt_uclibc_le_arc700_linux_install.tar.gz ]; then
  mkdir -p arc && cd arc
  tar -xf ../arc_gnu_2017.09_prebuilt_uclibc_le_arc700_linux_install.tar.gz
  mv arc_gnu_2017.09_prebuilt_uclibc_le_arc700_linux_install/* . 2>/dev/null || true
  rmdir arc_gnu_2017.09_prebuilt_uclibc_le_arc700_linux_install 2>/dev/null || true
  cd ..
fi
# POWERPC
if [ -f cross-compiler-powerpc.tar.gz ]; then
  mkdir -p powerpc && cd powerpc
  tar -xf ../cross-compiler-powerpc.tar.gz
  mv cross-compiler-powerpc/* . 2>/dev/null || true
  rmdir cross-compiler-powerpc 2>/dev/null || true
  cd ..
fi
# SH4
if [ -f cross-compiler-sh4.tar.gz ]; then
  mkdir -p sh4 && cd sh4
  tar -xf ../cross-compiler-sh4.tar.gz
  mv cross-compiler-sh4/* . 2>/dev/null || true
  rmdir cross-compiler-sh4 2>/dev/null || true
  cd ..
fi
# MIPS
if [ -f cross-compiler-mips.tar.gz ]; then
  mkdir -p mips && cd mips
  tar -xf ../cross-compiler-mips.tar.gz
  mv cross-compiler-mips/* . 2>/dev/null || true
  rmdir cross-compiler-mips 2>/dev/null || true
  cd ..
fi
# MIPSEL
if [ -f cross-compiler-mipsel.tar.gz ]; then
  mkdir -p mipsel && cd mipsel
  tar -xf ../cross-compiler-mipsel.tar.gz
  mv cross-compiler-mipsel/* . 2>/dev/null || true
  rmdir cross-compiler-mipsel 2>/dev/null || true
  cd ..
fi
# X86_64
if [ -f cross-compiler-x86_64.tar.gz ]; then
  mkdir -p x86_64 && cd x86_64
  tar -xf ../cross-compiler-x86_64.tar.gz
  mv cross-compiler-x86_64/* . 2>/dev/null || true
  rmdir cross-compiler-x86_64 2>/dev/null || true
  cd ..
fi
# M68K
if [ -f cross-compiler-m68k.tar.gz ]; then
  mkdir -p m68k && cd m68k
  tar -xf ../cross-compiler-m68k.tar.gz
  mv cross-compiler-m68k/* . 2>/dev/null || true
  rmdir cross-compiler-m68k 2>/dev/null || true
  cd ..
fi
# SPARC
if [ -f cross-compiler-sparc.tar.gz ]; then
  mkdir -p sparc && cd sparc
  tar -xf ../cross-compiler-sparc.tar.gz
  mv cross-compiler-sparc/* . 2>/dev/null || true
  rmdir cross-compiler-sparc 2>/dev/null || true
  cd ..
fi
# I486
if [ -f cross-compiler-i486.tar.gz ]; then
  mkdir -p i486 && cd i486
  tar -xf ../cross-compiler-i486.tar.gz
  mv cross-compiler-i486/* . 2>/dev/null || true
  rmdir cross-compiler-i486 2>/dev/null || true
  cd ..
fi
# AARCH64
if [ -f aarch64-toolchain.tar.xz ]; then
  xz -d aarch64-toolchain.tar.xz
fi
if [ -f aarch64-toolchain.tar ]; then
  mkdir -p aarch64 && cd aarch64
  tar -xf ../aarch64-toolchain.tar
  rm ../aarch64-toolchain.tar
  aarch64_dir=$(find . -maxdepth 1 -type d ! -name . | head -n 1)
  if [ -n "$aarch64_dir" ]; then
    mv "$aarch64_dir"/* . 2>/dev/null || true
    rmdir "$aarch64_dir" 2>/dev/null || true
  fi
  cd ..
fi
# ARMV4L
if [ -f cross-compiler-armv4l.tar.gz ]; then
  mkdir -p armv4l && cd armv4l
  tar -xf ../cross-compiler-armv4l.tar.gz
  mv cross-compiler-armv4l/* . 2>/dev/null || true
  rmdir cross-compiler-armv4l 2>/dev/null || true
  cd ..
fi
# ARMV5L
if [ -f cross-compiler-armv5l.tar.gz ]; then
  mkdir -p armv5l && cd armv5l
  tar -xf ../cross-compiler-armv5l.tar.gz
  mv cross-compiler-armv5l/* . 2>/dev/null || true
  rmdir cross-compiler-armv5l 2>/dev/null || true
  cd ..
fi
# ARMV6L
if [ -f cross-compiler-armv6l.tar.gz ]; then
  mkdir -p armv6l && cd armv6l
  tar -xf ../cross-compiler-armv6l.tar.gz
  mv cross-compiler-armv6l/* . 2>/dev/null || true
  rmdir cross-compiler-armv6l 2>/dev/null || true
  cd ..
fi
# ARMV7L
if [ -f cross-compiler-armv7l.tar.bz2 ]; then
  mkdir -p armv7l && cd armv7l
  tar -xjf ../cross-compiler-armv7l.tar.bz2
  if [ -d cross-compiler-armv7l ]; then
    mv cross-compiler-armv7l/* . 2>/dev/null || true
    rmdir cross-compiler-armv7l 2>/dev/null || true
  fi
  rm ../cross-compiler-armv7l.tar.bz2
  cd ..
else
  echo "[WARN] armv7l failed to install"
fi
# CSKY GCC
if [ -f cross-compiler-csky.tar.gz ]; then
  mkdir -p csky-gcc && cd csky-gcc
  tar -xf ../cross-compiler-csky.tar.gz
  mv csky-gcc/* . 2>/dev/null || true
  rmdir csky-gcc 2>/dev/null || true
  rm ../cross-compiler-csky.tar.gz
  cd ..
fi

export PATH=/etc/xcompile/arc/bin:$PATH
export PATH=/etc/xcompile/powerpc/bin:$PATH
export PATH=/etc/xcompile/sh4/bin:$PATH
export PATH=/etc/xcompile/mips/bin:$PATH
export PATH=/etc/xcompile/mipsel/bin:$PATH
export PATH=/etc/xcompile/x86_64/bin:$PATH
export PATH=/etc/xcompile/m68k/bin:$PATH
export PATH=/etc/xcompile/sparc/bin:$PATH
export PATH=/etc/xcompile/i486/bin:$PATH
export PATH=/etc/xcompile/aarch64/bin:$PATH
export PATH=/etc/xcompile/armv4l/bin:$PATH
export PATH=/etc/xcompile/armv5l/bin:$PATH
export PATH=/etc/xcompile/armv6l/bin:$PATH
export PATH=/etc/xcompile/armv7l/bin:$PATH
export PATH=/etc/xcompile/csky-gcc/bin:$PATH

for d in arc powerpc sh4 mips mipsel x86_64 m68k sparc i486 aarch64 armv4l armv5l armv6l armv7l csky-gcc; do
  echo "export PATH=/etc/xcompile/$d/bin:\$PATH" >> ~/.bashrc
  if [ -d "/etc/xcompile/$d/bin" ]; then
    for bin in /etc/xcompile/$d/bin/*; do
      [ -f "$bin" ] && sudo ln -sf "$bin" /usr/local/bin/$(basename "$bin")
    done
  fi
done

rm -rf *.tar.gz *.tar.xz *.bz
if [ -n "$BASH_VERSION" ]; then
  source ~/.bashrc
else
  . ~/.bashrc
fi
