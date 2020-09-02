/*
Like every other hardware, we could interact with PCI on x86
using only IO instructions and memory operations.

But PCI is a complex communication protocol that the Linux kernel
implements beautifully for us, so let's use the kernel API.

This example relies on the QEMU "edu" educational device.
Grep QEMU source for the device description, and keep it open at all times!

-   edu device source and spec in QEMU tree:
	- https://github.com/qemu/qemu/blob/v2.7.0/hw/misc/edu.c
	- https://github.com/qemu/qemu/blob/v2.7.0/docs/specs/edu.txt
-   http://www.zarb.org/~trem/kernel/pci/pci-driver.c inb outb runnable example (no device)
-   LDD3 PCI chapter
-   another QEMU device + module, but using a custom QEMU device:
	- https://github.com/levex/kernel-qemu-pci/blob/31fc9355161b87cea8946b49857447ddd34c7aa6/module/levpci.c
	- https://github.com/levex/kernel-qemu-pci/blob/31fc9355161b87cea8946b49857447ddd34c7aa6/qemu/hw/char/lev-pci.c
-   https://is.muni.cz/el/1433/podzim2016/PB173/um/65218991/ course given by the creator of the edu device.
	In Czech, and only describes API
-   http://nairobi-embedded.org/linux_pci_device_driver.html
*/

#include <linux/processor.h>
#include <linux/sched.h>
#include <asm/uaccess.h> /* put_user */
#include <asm/io.h>
#include <linux/cdev.h> /* cdev_ */
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/kprobes.h>
#include <linux/bpf.h>
#include <linux/filter.h>


/* Each PCI device has 6 BAR IOs (base address register) as per the PCI spec.
 *
 * Each BAR corresponds to an address range that can be used to communicate with the PCI.
 *
 * Eech BAR is of one of the two types:
 *
 * - IORESOURCE_IO: must be accessed with inX and outX
 * - IORESOURCE_MEM: must be accessed with ioreadX and iowriteX
 *   	This is the saner method apparently, and what the edu device uses.
 *
 * The length of each region is defined BY THE HARDWARE, and communicated to software
 * via the configuration registers.
 *
 * The Linux kernel automatically parses the 64 bytes of standardized configuration registers for us.
 *
 * QEMU devices register those regions with:
 *
 *     memory_region_init_io(&edu->mmio, OBJECT(edu), &edu_mmio_ops, edu,
 *                     "edu-mmio", 1 << 20);
 *     pci_register_bar(pdev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &edu->mmio);
 *

 * Through write operation you can put the kprobe_target kernel symbol string at offset 16
 * Through write operation at offset 0/4 you can register/unregister a kprobe on the kernel symbol 
 * contained at offset 16

 *	+----+------------------------------+
 *	|  0 |     	REGISTER_KPROBE 		|
 *	+----+------------------------------+
 *	|  4 |     	UNREGISTER_KPROBE  		|
 *	+----+------------------------------+
 *	|  8 | LOAD KPROBE_TARGET FROM HOST |
 *	+----+------------------------------+
 *	| 12 |            ---	          	|	?bpf program len?
 *	+----+------------------------------+
 *	| 16 |  	KPROBE_TARGET[0] 		|
 *	+----+------------------------------+
 *	| 20 |   	KPROBE_TARGET[1]  		|
 *	+----+------------------------------+
 *	| 24 |   	KPROBE_TARGET[2]  		|
 *	+----+------------------------------+
 *	| 28 |   	KPROBE_TARGET[3]  		|
 *	+----+------------------------------+
 *	| 32 |   	  						|
 *	+----+								+
 *	| 36 |   	  BPF PROGRAM			|	?BPF PROGRAM? -> THIS AREA HAS MAX SIZE
 *	+----+								+	 OF 4096 INSTRUCTIONS
 *	| 40 |		   			  			|    SIZEOF(INSNS) * 4096(MAXBPF INSTRUCT)
 *	+----+------------------------------+
 *					...
 *					...
 *
 *
 *
 **/



#define NEWDEV_REG_PCI_BAR      0
#define NEWDEV_BUF_PCI_BAR      1
#define DEV_NAME "testnewdev"
#define EDU_DEVICE_ID 0x11ea

#define NEWDEV_REG_STATUS_IRQ   8
#define NEWDEV_REG_RAISE_IRQ    8
#define NEWDEV_REG_LOWER_IRQ    12

#define QEMU_VENDOR_ID 0x1234


#define BPF_PROG_LEN 			12
#define BPF_PROG_OFFSET 		32

#define KPROBE_TARGET_OFFSET	16
#define KPROBE_TARGET_SIZE		4

#define MAX_SYMBOL_LEN			32



MODULE_LICENSE("GPL");

static struct pci_device_id pci_ids[] = {
	{ PCI_DEVICE(QEMU_VENDOR_ID, EDU_DEVICE_ID), },
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, pci_ids);

static int pci_irq;
static int major;
static struct pci_dev *pdev;
static void __iomem *io;


static ssize_t read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
	ssize_t ret;
	u32 kbuf;

	pr_info("READ SIZE=%ld, OFF=%lld", len, *off);

	if (*off % 4 || len == 0) {
		pr_info("read off=%lld or size=%ld error, NOT ALIGNED 4!\n", *off, len);
		ret = 0;
	} else {
		kbuf = ioread32(io + *off);
		if (copy_to_user(buf, (void *)&kbuf, 4)) {
			ret = -EFAULT;
		} else {
			ret = len;
			*off += 4;
		}
	}
	pr_info("READ\n");



	return ret;
}

static ssize_t write(struct file *filp, const char __user *buf, size_t len, loff_t *off)
{
	ssize_t ret;
	u32 kbuf;
	pr_info("WRITE SIZE=%ld, OFF=%lld", len, *off);
	ret = len;
	if (!(*off % 4)) {
		if (copy_from_user((void *)&kbuf, buf, 4) ) { // || len != 4) {
			ret = -EFAULT;
		} else {
			iowrite32(kbuf, io + *off);

			*off += 4;
		}
	}
	else{
		pr_info("write off=%lld or size=%ld error, NOT ALIGNED 4!\n", *off, len);
	}
	pr_info("WRITE\n");
	return ret;
}

static loff_t llseek(struct file *filp, loff_t off, int whence)
{
	loff_t newpos;

  switch(whence) {
   case 0: /* SEEK_SET */
    newpos = off;
    break;

   case 1: /* SEEK_CUR */
    newpos = filp->f_pos + off;
    break;

   default: /* can't happen */
    return -EINVAL;
  }
  if (newpos<0) return -EINVAL;
  filp->f_pos = newpos;
  return newpos;
}

/* These fops are a bit daft since read and write interfaces don't map well to IO registers.
 *
 * One ioctl per register would likely be the saner option. But we are lazy.
 *
 * We use the fact that every IO is aligned to 4 bytes. Misaligned reads means EOF. */
static struct file_operations fops = {
	.owner   = THIS_MODULE,
	.llseek  = llseek,
	.read    = read,
	.write   = write,
};

static irqreturn_t irq_handler(int irq, void *dev){
	int devi;
	irqreturn_t ret;
	u32 irq_status;

	devi = *(int *)dev;
	if (devi == major) {
		irq_status = ioread32(io + NEWDEV_REG_STATUS_IRQ);

		//handle
		pr_info("interrupt irq = %d dev = %d irq_status = %llx\n",
				irq, devi, (unsigned long long)irq_status);
		/* Must do this ACK, or else the interrupts just keeps firing. */
		iowrite32(irq_status, io + NEWDEV_REG_LOWER_IRQ);
		ret = IRQ_HANDLED;
	} else {
		ret = IRQ_NONE;
	}
	return ret;
}

/**
 * Called just after insmod if the hardware device is connected,
 * not called otherwise.
 *
 * 0: all good
 * 1: failed
 */
static int pci_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
	u8 val;

	pr_info("pci_probe\n");
	major = register_chrdev(0, DEV_NAME, &fops);
	pdev = dev;
	if (pci_enable_device(dev) < 0) {
		dev_err(&(pdev->dev), "pci_enable_device\n");
		goto error;
	}
	if (pci_request_region(dev, NEWDEV_REG_PCI_BAR, "myregion0")) {
		dev_err(&(pdev->dev), "pci_request_region0\n");
		goto error;
	}
	io = pci_iomap(pdev, NEWDEV_REG_PCI_BAR, pci_resource_len(pdev, NEWDEV_REG_PCI_BAR));

	/* IRQ setup. */
	pci_read_config_byte(dev, PCI_INTERRUPT_LINE, &val);
	pci_irq = val;
	if (request_irq(pci_irq, irq_handler, IRQF_SHARED, "pci_irq_handler0", &major) < 0) {
		dev_err(&(dev->dev), "request_irq\n");
		goto error;
	}

	pr_info("pci_probe COMPLETED SUCCESSFULLY\n");

	return 0;
error:
	return 1;
}

static void pci_remove(struct pci_dev *dev)
{
	pr_info("pci_remove\n");
	// pci_release_region(dev, NEWDEV_REG_PCI_BAR);
	pci_release_region(dev, NEWDEV_BUF_PCI_BAR);
	unregister_chrdev(major, DEV_NAME);
}

static struct pci_driver pci_driver = {
	.name     = DEV_NAME,
	.id_table = pci_ids,
	.probe    = pci_probe,
	.remove   = pci_remove,
};

static int myinit(void)
{
	if (pci_register_driver(&pci_driver) < 0) {
		return 1;
	}

	return 0;
}

static void myexit(void)
{
	pci_unregister_driver(&pci_driver);

}

module_init(myinit);
module_exit(myexit);