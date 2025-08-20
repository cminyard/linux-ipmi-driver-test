# Linux IPMI driver test framework and suite

This is a framework for testing the IPMI driver and a set of tests to
run against it.

Currently this only works on x86\_64 machines running in a x86\_64
version of qemu.

This consists of the following pieces:

* A test helper program to do things on the target for the test harness.

* A Yocto build setup to build an image with the test helper on it.

* An ipmi\_sim setup to simulate a BMC and allow injecting things into
  the IPMI driver for testing.  This hooks to qemu via the external
  IPMI interface.
  
* A test harness and tests.

Requirements:

* OpenIPMI library and ipmi\_sim

* gensio library

* qemu-system-x86_64

# Building

To use this, you must first build the Yocto image with the test helper
on it.  This will run the driver under test.  Go to the yocto
directory and run BuildYocto.  This takes a while, so start this in
the evening and come back in the morning.

If you need to debug on the target, you will need to add that
information to the target image.  To do this:

    cd yocto/poky
	source oe-init-build-env
	vi conf/local.conf

Near the end of `local.conf` there will be a line talking about
enabled debugging, uncomment that line.  Then:

    bitbake core-image-minimal
	
When you boot the new image it will have debugging.  You can transfer
`ipmi_test_helper.c` to the target, compile it with:

    gcc -o ipmi_test_helper -g -Wall ipmi_test_helper.c -lgensio -lgensioosh

and get to debugging.

Type "make" in the main directory to build the test harness and tests.

# Setup

Note that this does do not use the Yocto-built kernel, you are testing
a kernel, so you have to supply that kernel.  You must compile all the
IPMI parts as modules, and you must compile the i2c-i801 bus driver as
a module.  Don't make anything else modules.  The kernel must be
capable of booting and working without any other modules.  There is a
kernel.config file as an example of what you would need.

Copy the bzImage for the kernel to test into the current directory.
Then start the IPMI BMC simulator and the virtual machine with:

    ipmi_sim -c lan.conf -f ipmisim1.emu -p
  
The virtual machine will have the following ports available:

* 9001 - The IPMI LAN interface.

* 9002 - The IPMI connection between ipmi_sim and qemu.  Don't mess
  with this.
  
* 9003 - The console serial port.  This is connected via IPMI SOL
  through ipmi_sim, so don't mess with this directly.
  
* 9004 - A serial port with a getty on it so you can log in without
  going through IPMI SOL.  It's not a console, though.
  
* 5556 - This is an ssh connection to the target, you will use this
  to transfer modules to the target.
  
* 2000 - The IPMI test helper connection.

You can power the VM on with:

    ipmitool -U ipmiusr -P test -I lanplus -H localhost -p 9001 chassis power on
	
Or you can use ipmicmd:

    openipmicmd -k 'f 0 0 2 1' lan -U ipmiusr -P test -p 9001 localhost
	
You can connect to the console with:

    solterm lan -U ipmiusr -P test -p 9001 localhost

After this, transfer the modules to the target:

    scp -P 5556 Zx86_64/drivers/char/ipmi/*.ko \
	    Zx86_64/drivers/i2c/busses/i2c-i801.ko root@localhost:

Note that my kernel build is in Zx86_64, you need to use the location
of your kernel build for this.

# Running

After that, compile with:

    gcc -o ipmi_driver_test -g -Wall ipmi_driver_test.c -lgensio -lgensioosh \
	-l OpenIPMI -l gensio_openipmi_oshandler

Then run it:

    ./ipmi_driver_test
	
Note that the test will power on and off the VM.

To list all the tests, do:

    ./ipmi_driver_test -l

And to run an individual test, do:

    ./ipmi_driver_test <testnum>

Note that if a test fails, the program stops but does not shut the VM
down or change anything.

# Handy commands

Command to remove all modules:

    rmmod `lsmod | tail -n +2 | awk '{ print $1 }'`
	
Command to close device 0 on the VM:

    echo "Close 0 0" | gensiot -i 'stdio(self)' 'tcp,localhost,2000'
