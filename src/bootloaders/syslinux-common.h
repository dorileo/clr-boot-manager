/*
 * This file is part of clr-boot-manager.
 *
 * Copyright © 2020 Intel Corporation
 *
 * clr-boot-manager is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1
 * of the License, or (at your option) any later version.
 */

#pragma once

struct SyslinuxContext {
        KernelArray *kernel_queue;
        char *syslinux_cmd;
        char *sgdisk_cmd;
        char *base_path;
};

typedef bool (*command_writer)(struct SyslinuxContext *ctx, const char *prefix, char *boot_device);

/**
 * Common implementation of get_default_kernel for both syslinux and extlinux
 */
char *syslinux_common_get_default_kernel(const BootManager *manager);

/* Queue kernel to be added to conf */
bool syslinux_common_install_kernel(const BootManager *manager, const Kernel *kernel);

/* Actually creates the whole conf by iterating through the queued kernels */
bool syslinux_common_set_default_kernel(const BootManager *manager, const Kernel *default_kernel);

/* Cleans up the syslinux bootmanager's instance/private data */
void syslinux_common_destroy(const BootManager *manager);

/* Common syslinux boot loader initialization */
bool syslinux_common_init(const BootManager *manager, command_writer writer);

/* Installs both syslinux and extlinux bootloaders */
bool syslinux_common_install(const BootManager *manager);

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 expandtab:
 * :indentSize=8:tabSize=8:noTabs=true:
 */
