#include <linux/init.h>
#include <linux/kd.h>
#include <linux/kernel.h>
#include <linux/tracehook.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/lsm_hooks.h>
#include <linux/xattr.h>
#include <linux/security.h>
#include <linux/capability.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/proc_fs.h>
#include <linux/magic.h>
#include <linux/ctype.h>
#include <linux/swap.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/tty.h>
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/parser.h>
#include <linux/nfs_mount.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/posix-timers.h>
#include <linux/syslog.h>
#include <linux/user_namespace.h>
#include <linux/export.h>
#include <linux/msg.h>
#include <linux/shm.h>
#include <linux/gfp.h>

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/list.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/fsnotify.h>
#include <linux/path.h>
#include <linux/fdtable.h>
#include <linux/binfmts.h>
#include <linux/time.h>

#include <linux/usb.h>
#include <linux/usb/hcd.h>

MODULE_LICENSE("GPLv3");
MODULE_AUTHOR("Chenvia");


static int HARD_VEND;
static int HARD_PROD;
static char *HARD_SERI;

struct USBCred {

	int vendor;
	int product;
	char serial[128];
};

static struct USBCred create_creds_device(struct usb_device *dev) {
	
        struct USBCred creds;
	
	creds.vendor = dev->descriptor.idVendor;
	creds.product = dev->descriptor.idProduct;

	if((dev->serial) == NULL)
	{
		strcpy(creds.serial, "(null)");
	} else {
		strcpy(creds.serial, dev->serial);
	}
	
	return creds;
}

static struct USBCred create_creds_hub(struct usb_bus *bus) {

	struct USBCred creds;
	
	creds.vendor = bus->root_hub->descriptor.idVendor;
	creds.product = bus->root_hub->descriptor.idProduct;

	if((bus->root_hub->serial) == NULL)
	{
		strcpy(creds.serial, "(null)");
	} else {
		strcpy(creds.serial, bus->root_hub->serial);
	}
	
	return creds;
}


static int check_usb_creds(struct USBCred usb_data) {

	if(usb_data.vendor != HARD_VEND && usb_data.product != HARD_PROD && strcmp(usb_data.serial, HARD_SERI))
	{
	    return 1;
	} else 
	{
	    return 0; 
	}
}

static int find_usb_device(void) {

    int id;
    int chix;
	
    struct USBCred cred;
	
    struct usb_bus *bus; 
    struct usb_device *dev, *childdev = NULL;
	
    HARD_VEND = 0x26bd;
    HARD_PROD = 0x9917;
    HARD_SERI = "070172966462EB10";
  
    mutex_lock(&usb_bus_idr_lock);
	
    //loop though all usb buses
    idr_for_each_entry(&usb_bus_idr, bus, id)
    {  	     		
        cred = create_creds_hub(bus);
        
        //Check creds of usb buses
        if(check_usb_creds(cred) == 0)
        {
            mutex_unlock(&usb_bus_idr_lock);
            return 0;
        }
	

        dev = bus->root_hub;
        usb_hub_for_each_child(dev, chix, childdev)
        {
            if(childdev)
            {		
                usb_lock_device(childdev);
                cred = create_creds_device(childdev);

                if(check_usb_creds(cred) == 0)
                {
                    usb_unlock_device(childdev);
                    mutex_unlock(&usb_bus_idr_lock);
                    return 0;		
                } else {
                    usb_unlock_device(childdev);	
                }

            }
        }
    }

    mutex_unlock(&usb_bus_idr_lock);
    return -EPERM;
}

static int rootplug_bprm_check_security (struct linux_binprm *bprm) {

    int i;
	const char *whitelist[13];

	/** Certain processes are called before USB is online, as such
            the system cannot boot without these being whitelisted     **/

        whitelist[0] = "/sbin/modprobe";
        whitelist[1] = "/init";
        whitelist[2] = "/bin/busybox";
        whitelist[3] = "/scripts/init-top/all_generic_ide";
        whitelist[4] = "/scripts/init-top/blacklist";
        whitelist[5] = "/scripts/init-top/udev";
        whitelist[6] = "/lib/systemd/systemd-udevd";
        whitelist[7] = "/sbin/udevadm";
        whitelist[8] = "/scripts/init-premount/amd64_microcode";
        whitelist[9] = "/sbin/wait-for-root";
        whitelist[10] = "/scripts/init-bottom/udev";
		whitelist[11] = "/scripts/local-bottom/ntfs_3g";
		whitelist[12] = "/sbin/wait-for-root";

        for(i = 0; i < sizeof(whitelist)/sizeof(whitelist[0]); ++i) {            
            if(strcmp(bprm->filename, whitelist[i]) == 0) {
                return 0;
            }
        }

        //Process running as root
	if (bprm->cred->egid.val == 0) {
	    if (find_usb_device() != 0) {
                return -EPERM;
            } else {
                return 0;
	    }
	
        } else {
            /* Process is not running as root, as such is out of scope */
            return 0;
        }
}

static struct security_hook_list rootplug_hooks[] = {
	
        LSM_HOOK_INIT(bprm_check_security, rootplug_bprm_check_security),
};


static __init int rootplug_init(void) {
	
	security_add_hooks(rootplug_hooks, ARRAY_SIZE(rootplug_hooks), "rootplug");
	
	printk(KERN_ALERT "Rootplug: module initialised\n");

	return 0;
}

DEFINE_LSM(rootplug) = {
        .name = "rootplug",
        .init = rootplug_init,
};


