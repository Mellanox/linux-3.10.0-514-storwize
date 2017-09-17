/*
 * Copyright (c) 2017, Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/proc_fs.h>
#include <linux/mlx5/driver.h>
#include "mlx5_core.h"

#define MLX5_EXTRACT_C(source, offset, size)	\
((((unsigned)(source)) >> (offset)) & MLX5_ONES32(size))
#define MLX5_EXTRACT(src, start, len)		\
(((len) == 32) ? (src) : MLX5_EXTRACT_C(src, start, len))
#define MLX5_ONES32(size)			\
((size) ? (0xffffffff >> (32 - (size))) : 0)
#define MLX5_MASK32(offset, size)		\
(MLX5_ONES32(size) << (offset))
#define MLX5_MERGE_C(rsrc1, rsrc2, start, len)  \
((((rsrc2) << (start)) & (MLX5_MASK32((start), (len)))) | \
((rsrc1) & (~MLX5_MASK32((start), (len)))))
#define MLX5_MERGE(rsrc1, rsrc2, start, len)	\
(((len) == 32) ? (rsrc2) : MLX5_MERGE_C(rsrc1, rsrc2, start, len))

#define MLX5_PROTECTED_CR_SPCAE_DOMAIN 0x6

enum {
	UNLOCK,
	LOCK,
	CAP_ID = 0x9,
	IFC_MAX_RETRIES = 2048
};

enum {
	PCI_CTRL_OFFSET = 0x4,
	PCI_COUNTER_OFFSET = 0x8,
	PCI_SEMAPHORE_OFFSET = 0xc,

	PCI_ADDR_OFFSET = 0x10,
	PCI_ADDR_BIT_LEN = 30,

	PCI_DATA_OFFSET = 0x14,

	PCI_FLAG_BIT_OFFS = 31,

	PCI_SPACE_BIT_OFFS = 0,
	PCI_SPACE_BIT_LEN = 16,

	PCI_SIZE_VLD_BIT_OFFS = 28,
	PCI_SIZE_VLD_BIT_LEN = 1,

	PCI_STATUS_BIT_OFFS = 29,
	PCI_STATUS_BIT_LEN = 3,
};


/* iter func */
struct mlx5_crdump_iter {
	struct mlx5_fw_crdump *dump;
	u32 cur_index;
	u32 cur_data;
};

static int mlx5_pciconf_wait_on_flag(struct mlx5_core_dev *dev,
				     u8 expected_val)
{
	struct mlx5_priv *priv = &dev->priv;
	struct mlx5_fw_crdump *crdump = priv->health.crdump;
	int retries = 0;
	u32 flag;
	int ret;

	do {
		if (retries > IFC_MAX_RETRIES)
			return -EBUSY;
		ret = pci_read_config_dword(dev->pdev,
					    crdump->vsec_addr +
					    PCI_ADDR_OFFSET,
					    &flag);
		flag = MLX5_EXTRACT(flag, PCI_FLAG_BIT_OFFS, 1);
		retries++;
		if ((retries & 0xf) == 0)
			usleep_range(1000, 2000);
	} while (flag != expected_val);
	return 0;
}

static int mlx5_pciconf_read(struct mlx5_core_dev *dev,
			     unsigned int offset,
			     u32 *data)
{
	struct mlx5_priv *priv = &dev->priv;
	struct mlx5_fw_crdump *crdump = priv->health.crdump;
	u32 address;
	int ret;

	if (MLX5_EXTRACT(offset, 31, 1))
		return -EINVAL;
	address = MLX5_MERGE(offset, 0, PCI_FLAG_BIT_OFFS, 1);
	ret = pci_write_config_dword(dev->pdev,
				     crdump->vsec_addr +
				     PCI_ADDR_OFFSET,
				     address);
	if (ret)
		goto out;
	ret = mlx5_pciconf_wait_on_flag(dev, 1);
	if (ret)
		goto out;
	ret = pci_read_config_dword(dev->pdev,
				    crdump->vsec_addr +
				    PCI_DATA_OFFSET,
				    data);
out:
	return ret;
}

static int mlx5_block_op_pciconf(struct mlx5_core_dev *dev,
			  unsigned int offset, u32 *data,
			  int length)
{
	int read = length;
	int i;

	if (length % 4)
		return -EINVAL;
	for (i = 0; i < length; i += 4) {
		if (mlx5_pciconf_read(dev, offset + i, &data[(i >> 2)])) {
			read = i;
			goto cleanup;
		}
	}
cleanup:
	return read;
}

static int mlx5_pciconf_set_addr_space(struct mlx5_core_dev *dev, u16 space)
{
	struct mlx5_priv *priv = &dev->priv;
	struct mlx5_fw_crdump *crdump = priv->health.crdump;
	int ret = 0;
	u32 val;

	ret = pci_read_config_dword(dev->pdev,
				    crdump->vsec_addr +
				    PCI_CTRL_OFFSET,
				    &val);
	if (ret)
		goto out;

	val = MLX5_MERGE(val, space, PCI_SPACE_BIT_OFFS, PCI_SPACE_BIT_LEN);
	ret = pci_write_config_dword(dev->pdev,
				     crdump->vsec_addr +
				     PCI_CTRL_OFFSET,
				     val);
	if (ret)
		goto out;

	ret = pci_read_config_dword(dev->pdev,
				    crdump->vsec_addr +
				    PCI_CTRL_OFFSET,
				    &val);
	if (ret)
		goto out;

	if (MLX5_EXTRACT(val, PCI_STATUS_BIT_OFFS, PCI_STATUS_BIT_LEN) == 0)
		return -EINVAL;

	if ((space == MLX5_PROTECTED_CR_SPCAE_DOMAIN) &&
	    (!MLX5_EXTRACT(val, PCI_SIZE_VLD_BIT_OFFS, PCI_SIZE_VLD_BIT_LEN))) {
		mlx5_core_warn(dev, "Failed to get protected cr space size, valid bit not set");
		return -EINVAL;
	}

	return 0;
out:
	return ret;
}
 
static int mlx5_pciconf_set_protected_addr_space(struct mlx5_core_dev *dev,
						 u32 *ret_space_size) {
	struct mlx5_priv *priv = &dev->priv;
	struct mlx5_fw_crdump *crdump = priv->health.crdump;
	int ret;

	if (!ret_space_size)
		return -EINVAL;

	*ret_space_size = 0;

	ret = mlx5_pciconf_set_addr_space(dev, MLX5_PROTECTED_CR_SPCAE_DOMAIN);
	if (ret)
		return ret;

	ret = pci_read_config_dword(dev->pdev,
				    crdump->vsec_addr +
				    PCI_ADDR_OFFSET,
				    ret_space_size);
	if (ret) {
		mlx5_core_warn(dev, "Failed to get read protected cr space size");
		return ret;
	}

	*ret_space_size = MLX5_EXTRACT(*ret_space_size, 0, PCI_ADDR_BIT_LEN);

	return 0;
}

static int mlx5_pciconf_cap9_sem(struct mlx5_core_dev *dev, int state)
{
	struct mlx5_priv *priv = &dev->priv;
	struct mlx5_fw_crdump *crdump = priv->health.crdump;
	u32 counter = 0;
	int retries = 0;
	u32 lock_val;
	int ret;

	if (state == UNLOCK) {
		ret = pci_write_config_dword(dev->pdev,
					     crdump->vsec_addr +
					     PCI_SEMAPHORE_OFFSET,
					     UNLOCK);
		if (ret)
			goto out;
	} else {
		do {
			if (retries > IFC_MAX_RETRIES)
				return -EBUSY;
			ret = pci_read_config_dword(dev->pdev,
						    crdump->vsec_addr +
						    PCI_SEMAPHORE_OFFSET,
						    &lock_val);
			if (ret)
				goto out;
			if (lock_val) {
				retries++;
				usleep_range(1000, 2000);
				continue;
			}
			ret = pci_read_config_dword(dev->pdev,
						    crdump->vsec_addr +
						    PCI_COUNTER_OFFSET,
						    &counter);
			if (ret)
				goto out;
			ret = pci_write_config_dword(dev->pdev,
						     crdump->vsec_addr +
						     PCI_SEMAPHORE_OFFSET,
						     counter);
			if (ret)
				goto out;
			ret = pci_read_config_dword(dev->pdev,
						    crdump->vsec_addr +
						    PCI_SEMAPHORE_OFFSET,
						    &lock_val);
			if (ret)
				goto out;
			retries++;
		} while (counter != lock_val);
	}
	return 0;
out:
	return ret;
}

int mlx5_crdump_iter_next(struct mlx5_crdump_iter *iter)
{
	int ret = -1;

	/* check if we are at the end */
	mutex_lock(&iter->dump->crspace_mutex);
	if (iter->cur_index >= iter->dump->crspace_size)
		goto unlock;

	/* if not, read the next data */
	iter->cur_data = swab32(readl(&iter->dump->crspace[iter->cur_index]));
	iter->cur_index += 4;
	ret = 0;

unlock:
	mutex_unlock(&iter->dump->crspace_mutex);
	return ret;
}

struct mlx5_crdump_iter *mlx5_crdump_iter_init(struct mlx5_fw_crdump *dump)
{
	struct mlx5_crdump_iter *iter;

	iter = kzalloc(sizeof(*iter), GFP_KERNEL);
	if (!iter)
		return NULL;

	iter->dump = dump;
	iter->cur_index = 0;

	if (mlx5_crdump_iter_next(iter)) {
		kfree(iter);
		return NULL;
	}

	return iter;
}

void mlx5_crdump_iter_read(struct mlx5_crdump_iter *iter,
			   u32 *data, u32 *offset)
{
	*data = iter->cur_data;
	*offset = iter->cur_index - 4;
}

/* seq func */
static void *mlx5_crdump_seq_start(struct seq_file *file, loff_t *pos)
{
	struct mlx5_crdump_iter *iter;
	loff_t n = *pos;

	iter = mlx5_crdump_iter_init(file->private);
	if (!iter)
		return NULL;

	while (n--) {
		if (mlx5_crdump_iter_next(iter)) {
			kfree(iter);
			return NULL;
		}
	}

	return iter;
}

static void *mlx5_crdump_seq_next(struct seq_file *file, void *iter_ptr,
				  loff_t *pos)
{
	struct mlx5_crdump_iter *iter = iter_ptr;

	(*pos)++;

	if (mlx5_crdump_iter_next(iter)) {
		kfree(iter);
		return NULL;
	}

	return iter;
}

static void mlx5_crdump_seq_stop(struct seq_file *file, void *iter_ptr)
{
	/* nothing for now */
}

static int mlx5_crdump_seq_show(struct seq_file *file, void *iter_ptr)
{
	struct mlx5_crdump_iter *iter = iter_ptr;
	u32 data;
	u32 offset;

	if (!iter)
		return 0;

	mlx5_crdump_iter_read(iter, &data, &offset);

	seq_printf(file, "0x%08x 0x%08x\n", offset, cpu_to_be32(data));

	return 0;
}

static const struct seq_operations mlx5_crdump_seq_ops = {
	.start = mlx5_crdump_seq_start,
	.next  = mlx5_crdump_seq_next,
	.stop  = mlx5_crdump_seq_stop,
	.show  = mlx5_crdump_seq_show,
};

static int mlx5_crdump_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	int ret;

	ret = seq_open(file, &mlx5_crdump_seq_ops);
	if (ret)
		return ret;

	seq = file->private_data;
	seq->private = PDE_DATA(inode);

	return 0;
}

static const struct file_operations mlx5_crdump_fops = {
	.owner   = THIS_MODULE,
	.open    = mlx5_crdump_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release
};

int mlx5_cr_protected_capture(struct mlx5_core_dev *dev)
{
	struct mlx5_priv *priv = &dev->priv;
	void *cr_data = NULL;
	u32 total_len = 0;
	int ret = 0;

	if (!priv->health.crdump->vsec_addr)
		return -ENODEV;

	ret = mlx5_pciconf_cap9_sem(dev, LOCK);
	if (ret)
		return ret;

	ret = mlx5_pciconf_set_protected_addr_space(dev, &total_len);
	if (ret)
		goto unlock;

	cr_data = kcalloc(total_len, sizeof(u8), GFP_KERNEL);
	if (!cr_data) {
		ret = -ENOMEM;
		goto unlock;
	}

	ret = mlx5_block_op_pciconf(dev, 0, (u32 *)cr_data, total_len);
	if (ret < 0)
		goto free_mem;

	if (total_len != ret) {
		pr_warn("crdump failed to read full dump, read %d out of %u\n",
			ret, total_len);
		ret = -EINVAL;
		goto free_mem;
	}

	priv->health.crdump->crspace = cr_data;
	priv->health.crdump->crspace_size = total_len;
	ret = 0;

free_mem:
	if (ret)
		kfree(cr_data);
unlock:
	mlx5_pciconf_cap9_sem(dev, UNLOCK);
	return ret;
}

int mlx5_fill_cr_dump(struct mlx5_core_dev *dev)
{
	int ret = 0;

	if (!mlx5_core_is_pf(dev))
		return 0;

	mutex_lock(&dev->priv.health.crdump->crspace_mutex);
	if (dev->priv.health.crdump->crspace_size) {
		/* reading only at the first time */
		pr_debug("crdump was already taken, returning\n");
		goto unlock;
	}

	dev->priv.health.crdump->vsec_addr = pci_find_capability(dev->pdev, CAP_ID);
	if (!dev->priv.health.crdump->vsec_addr) {
		pr_warn("failed reading	vsec_addr\n");
		ret = -1;
		goto unlock;
	}

	kfree(dev->priv.health.crdump->crspace);
	dev->priv.health.crdump->crspace_size = 0;

	ret = mlx5_cr_protected_capture(dev);
	if (ret) {
		dev_err(&dev->pdev->dev, "failed capture crdump (err: %d)\n", ret);
		goto unlock;
	}

	mlx5_core_err(dev, "crdump: Crash snapshot collected to /proc/%s/%s/%s\n",
		MLX5_CORE_PROC, MLX5_CORE_PROC_CRDUMP,
		pci_name(dev->pdev));

unlock:
	mutex_unlock(&dev->priv.health.crdump->crspace_mutex);
	return ret;
}

int mlx5_crdump_init(struct mlx5_core_dev *dev)
{
	struct mlx5_priv *priv = &dev->priv;
	struct mlx5_fw_crdump *crdump;
	int ret = -1;

	if (!mlx5_core_is_pf(dev))
		return 0;

	priv->health.crdump = kzalloc(sizeof(*crdump), GFP_KERNEL);
	if (!priv->health.crdump)
		return -ENOMEM;

	crdump = priv->health.crdump;

	mutex_init(&crdump->crspace_mutex);

	if (mlx5_crdump_dir)
		if (!proc_create_data(pci_name(dev->pdev), S_IRUGO,
				      mlx5_crdump_dir, &mlx5_crdump_fops,
				      crdump)) {
			pr_warn("failed creating proc file\n");
			goto clean_mem;
		}

	return 0;

clean_mem:
	kfree(crdump);
	return ret;
}

void mlx5_crdump_cleanup(struct mlx5_core_dev *dev)
{
	struct mlx5_priv *priv = &dev->priv;
	struct mlx5_fw_crdump *crdump = priv->health.crdump;

	if (!mlx5_core_is_pf(dev))
		return;

	if (mlx5_crdump_dir)
		remove_proc_entry(pci_name(dev->pdev), mlx5_crdump_dir);

	if (crdump) {
		kfree(crdump->crspace);
		kfree(crdump);
	}
}
