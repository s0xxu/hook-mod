#include <linux/module.h>                                                                                                                                                                     
#include <linux/kernel.h>                                                                                                                                                                     
#include <linux/kprobes.h>                                                                                                                                                                    
#include <linux/ftrace.h>   
#include <linux/string.h>
#include <linux/syscalls.h>                                                                                                                                                                   
static struct kprobe kp;
static struct ftrace_ops ops;
static asmlinkage long (*orig_sys_openat)(struct pt_regs *regs);
typedef unsigned long (*kallsyms_lookup_t)(const char *sys_name);                                                                                                                                 
kallsyms_lookup_t kallsym_lookup;                                        


static long hook_sys_openat(struct pt_regs *regs) 
{

	char *str_buff = kmalloc(PATH_MAX, GFP_ATOMIC);
			if (str_buff == NULL) {
				pr_debug("KMALLOC RETURN NULL\n");
			}
			if (strncpy_from_user(str_buff, (const char __user *)regs->si, PATH_MAX) < 0) {
        			pr_debug("STRNCPY HOOK RETURN NULL");
			}
	pr_info("HOOKED dfd: %d path: %s flags: %d\n", (int)regs->di, str_buff, (int)regs->dx);
	kfree(str_buff);
	pr_info("HOOK sys_openat %px", orig_sys_openat);
	return orig_sys_openat(regs);
}


static void ftrace_hook_handler(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct ftrace_regs *fregs) 
{
		struct task_struct *task = current;
		struct pt_regs *regs = ftrace_get_regs(fregs);
		pr_info("PID: %d \n", task->pid);
		pr_info("ip %lx hook at %lx\n", ip, (unsigned long)hook_sys_openat);
		regs->ip = (unsigned long)hook_sys_openat; 
		
}	

static int ftrace_hook(unsigned long addr) 
{
	int ret; 
	ops.func = ftrace_hook_handler;
	ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;
	pr_info("flags: %lx func: %lx ", ops.flags, (unsigned long)ftrace_hook_handler, (unsigned long)ops.func);
	ret = ftrace_set_filter_ip(&ops, addr, 0, 0);
		if (ret < 0) {
			pr_info("ftrace filter ip fail\n");
			return -1;
		}
	ret = register_ftrace_function(&ops);										
		if (ret < 0) {
			pr_info("ftrace register fail\n");
			return -1;
		}												
	pr_info("ftrace register return no error\n");													
	pr_info("ftrace filter return no error\n");		
		return 0;
}
                                                                                                                                                                                              
static int __init init_mod(void)                                                                                                                                                              
{                                                                                                                                                                                             
	                pr_info("KERN MOD INIT\n");                                                                                                                                                     
			kp.symbol_name = "kallsyms_lookup_name";                                                                                                                              
			int ret = register_kprobe(&kp);                                                                                                                               
				if (ret < 0) {                                                                                                                                
					pr_info("kprobe register fail\n");                                                                             
				}                                                                                             

			pr_info("kallsyms addr %lx\n", kp.addr);
			unregister_kprobe(&kp);
			kallsym_lookup = (kallsyms_lookup_t)kp.addr;
			unsigned long addr = kallsym_lookup("__x64_sys_openat");
			orig_sys_openat = addr + MCOUNT_INSN_SIZE;
			ftrace_hook(addr);
				return 0;
}

static void __exit exit_mod(void)
{
	                pr_info("KERN MOD EXIT\n");
			
}

module_init(init_mod);
module_exit(exit_mod);


MODULE_LICENSE("GPL");
MODULE_AUTHOR("s0xxu");
MODULE_DESCRIPTION("kernel hook mod for learning");

