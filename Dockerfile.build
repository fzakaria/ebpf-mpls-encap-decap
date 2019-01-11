FROM oraclelinux:7.6
MAINTAINER Farid Zakaria <farid.m.zakaria@gmail.com>

# Install deltarpm so we make yum installs faster
# https://www.certdepot.net/rhel7-get-started-delta-rpms/
RUN yum -y install deltarpm

# Update our yum repositories
RUN yum -y update

# Install all necessary development tools
RUN yum -y groupinstall "Development Tools"
RUN yum -y clean all

# Enable the developer repositories
# this is where the llvm-toolset-7 is located
RUN yum-config-manager --enable ol7_developer
# this is where devtoolset-7-gcc-c+ is located
RUN yum-config-manager --enable ol7_software_collections

# Install the kernel header files
# https://docs.oracle.com/cd/E93554_01/E63227/html/uek3_development.html
RUN yum -y install kernel-uek-devel kernel-headers

# Install development tools
RUN yum -y install llvm-toolset-7
# Need the 32bit glibc for static assert
RUN yum -y install glibc-devel.i686
RUN yum -y clean all

ENV CLANG /opt/rh/llvm-toolset-7/root/usr/bin/clang
ENV CLANG_FORMAT /opt/rh/llvm-toolset-7/root/usr/bin/clang-format
ENV LLC /opt/rh/llvm-toolset-7/root/usr/bin/llc

# Change the working directory to the source mounted directory
WORKDIR eBPF-mpls-encap-decap

ENTRYPOINT ["make"]