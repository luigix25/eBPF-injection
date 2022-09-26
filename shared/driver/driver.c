/*
 * Device driver for extensible paravirtualization QEMU device
 * 2022 Luigi Leonardi, Giacomo Pellicci
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <linux/module.h>
#include <linux/pci.h>

#include <bpf_injection_header.h>	


#define NEWDEV_BUF_PCI_BAR      1
#define DEV_NAME "newdev"
#define NEWDEV_DEVICE_ID 0x11ea
#define QEMU_VENDOR_ID 0x1234

#define NEWDEV_REG_STATUS_IRQ   0	//read
#define NEWDEV_REG_LOWER_IRQ    4	//write
#define NEWDEV_REG_RAISE_IRQ    8	//write (unused in this driver)
#define NEWDEV_REG_DOORBELL		8
#define NEWDEV_REG_SETAFFINITY	12

#define IOCTL_SCHED_SETAFFINITY 13
#define IOCTL_PROGRAM_INJECTION_RESULT_READY 14

#define BUFFER_SIZE 65536 + 4


MODULE_LICENSE("GPL");

static struct pci_device_id pci_ids[] = {
	{ PCI_DEVICE(QEMU_VENDOR_ID, NEWDEV_DEVICE_ID), },
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, pci_ids);

static int flag;
static int pci_irq;
static int major;
static struct pci_dev *pdev;
static void __iomem *bufmmio;
static void __iomem *bufmmio_user;
static DECLARE_WAIT_QUEUE_HEAD(wq);		//wait queue static declaration

static u8 *read_buffer;
static u16 available_data;				//data in the buffer

static ssize_t read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
	ssize_t ret = 0;

	// pr_info("READ SIZE=%ld, OFF=%lld", len, *off);
	wait_event_interruptible(wq, flag >= 1);
	
	//Fast Exit: unaligned read or reading 0 bytes
	if (*off % 4 || len == 0){
		// pr_info("read off=%lld or size=%ld error, NOT ALIGNED 4!\n", *off, len);
		return 0;
	}
	
	if(len > available_data)
		len = available_data;

	if (copy_to_user(buf, read_buffer + *off, len)) {
		ret = -EFAULT;
	} else {
		ret = len;
	} 

	*off += len;
	available_data -= len;

	pr_info("Available data %d\n",available_data);

	if(available_data == 0){
		flag = 0;
		*off = 0;
	}
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
			iowrite32(kbuf, bufmmio_user + *off);			
			*off += 4;
		}
	}
	else{
		pr_info("write off=%lld or size=%ld error, NOT ALIGNED 4!\n", *off, len);
	}
	pr_info("WRITE\n");
	return ret;
}

static long newdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {   
    switch (cmd) {
        case IOCTL_PROGRAM_INJECTION_RESULT_READY:
        	//bpf program result inserted in buffer area as bpf_injection_msg_t
        	pr_info("response is ready!!! [dev]\n");
        	iowrite32(1, bufmmio + NEWDEV_REG_DOORBELL);
        	//signal to device 
        	break;
        case IOCTL_SCHED_SETAFFINITY:
        {
        	// Retrieve the requested cpu from userspace
        	// Write in specific region in device to trigger the sched_setaffinity in host system
        	int requested_cpu;
        	if (copy_from_user(&requested_cpu, (int *)arg, sizeof(int))){
            	return -EACCES;
          	}
          	pr_info("IOCTL requested_cpu: %d\n", requested_cpu);
          	iowrite32(requested_cpu, bufmmio + NEWDEV_REG_SETAFFINITY);
        	break;
        }        	
	}
	return 0;
}

/* These fops are a bit daft since read and write interfaces don't map well to IO registers.
 * One ioctl per register would likely be the saner option. But we are lazy.
 * We use the fact that every IO is aligned to 4 bytes. Misaligned reads means EOF. */
static struct file_operations fops = {
	.owner   = THIS_MODULE,
	.read    = read,
	.write   = write,
	.unlocked_ioctl = newdev_ioctl,
};

//Top Half
static irqreturn_t irq_handler(int irq, void *dev){
	int devi;
	u32 irq_status;

	devi = *(int *)dev;
	if(devi != major){
		return IRQ_NONE;
	}

	irq_status = ioread32(bufmmio + NEWDEV_REG_STATUS_IRQ);

	//handle
	pr_info("interrupt irq = %d dev = %d irq_status = 0x%llx\n",
			irq, devi, (unsigned long long)irq_status);

	switch(irq_status){
		case PROGRAM_INJECTION:
			pr_info("case PROGRAM_INJECTION irq handler\n");
			pr_info("waking up interruptible process...\n");

			break;
		case PROGRAM_INJECTION_AFFINITY:
			pr_info("case PROGRAM_INJECTION_AFFINITY irq handler\n");
			break;
	}

	/* Must do this ACK, or else the interrupts just keeps firing. */
	iowrite32(irq_status, bufmmio + NEWDEV_REG_LOWER_IRQ);
	return IRQ_WAKE_THREAD;
}

//Bottom Half
static irqreturn_t bottom_half_handler(int irq, void *dev_id){

	u32 data;
	u32 payload_left;
	u32 offset;
	struct bpf_injection_msg_header myheader;

	data = ioread32(bufmmio_user);

	memcpy(&myheader, &data, sizeof(data));
	pr_info("  Version:%u\n  Type:%u\n  Payload_len:%u\n", myheader.version, myheader.type, myheader.payload_len);
	payload_left = myheader.payload_len;

	offset = 0;

	while(payload_left){
		data = ioread32(bufmmio_user + offset);
		memcpy(read_buffer + offset, &data,sizeof(data));

		if(payload_left < 4){
			payload_left = 0;
		} else {
			payload_left -= 4;
			offset += 4;
		}
	}

	available_data = myheader.payload_len +4;	//header followed by the payload

	pr_info("waking up interruptible process...\n");
	flag = 2;
	wake_up_interruptible(&wq);

	return IRQ_HANDLED;

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
	if(major < 0){
		dev_err(&(pdev->dev),"Can't allocate major\n");
		goto error;
	}

	pdev = dev;
	if (pci_enable_device(dev) < 0) {
		dev_err(&(pdev->dev), "pci_enable_device\n");
		goto chr_dev_label;
	}

	if (pci_request_region(dev, NEWDEV_BUF_PCI_BAR, "myregion1")) {
		dev_err(&(pdev->dev), "pci_request_region1\n");
		goto pci_enable_label;
	}
	bufmmio = pci_iomap(pdev, NEWDEV_BUF_PCI_BAR, pci_resource_len(pdev, NEWDEV_BUF_PCI_BAR));
	bufmmio_user = bufmmio + 16; //skipping memory mapped registers

	if(bufmmio == NULL){
		dev_err(&(pdev->dev), "pci_iomap\n");
		goto pci_request_region_label;
	}

	/* IRQ setup. */
	pci_read_config_byte(dev, PCI_INTERRUPT_LINE, &val);
	pci_irq = val;
	if (request_threaded_irq(pci_irq, irq_handler, bottom_half_handler, IRQF_SHARED, "pci_irq_newdev", &major) < 0) {
		dev_err(&(dev->dev), "request_irq\n");
		goto pci_iomap_label;
	}

	flag = 0;

	read_buffer = kmalloc(BUFFER_SIZE,GFP_KERNEL);
	if(read_buffer == NULL){
		dev_err(&(dev->dev), "kmalloc\n");
		goto request_irq_label;
	}

	available_data = 0;

	pr_info("pci_probe COMPLETED SUCCESSFULLY\n");

	return 0;

request_irq_label:
	free_irq(pci_irq, &major); 
pci_iomap_label:
	pci_iounmap(dev, bufmmio);
pci_request_region_label:
	pci_release_region(dev, NEWDEV_BUF_PCI_BAR);
pci_enable_label:
	pci_disable_device(dev);
chr_dev_label:
	unregister_chrdev(major, DEV_NAME);
error:
	return 1;
}

static void pci_remove(struct pci_dev *dev)
{
	pr_info("pci_remove\n");

	free_irq(pci_irq, &major); 

	pci_iounmap(dev, bufmmio);
	pci_release_region(dev, NEWDEV_BUF_PCI_BAR);
	pci_disable_device(dev);
	unregister_chrdev(major, DEV_NAME);

	kfree(read_buffer);
	read_buffer = NULL;
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