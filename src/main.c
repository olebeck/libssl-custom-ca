#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/sysmem.h>
#include <psp2/net/http.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/dirent.h>
#include <psp2/kernel/clib.h>
#include <stai/stai.h>

static const uint32_t SceHttp_library_nid = 0xE8F15CDE;
static const char custom_ca_dir[] = "ux0:data/ca/";

#define LOG(fmt, ...) sceClibPrintf("[libssl-custom-ca] " fmt, ##__VA_ARGS__)

static int module_uid_by_library_nid(uint32_t library_nid) {
    stai_module_info module_info;
    sceClibMemset(&module_info, 0, sizeof(module_info));
    module_info.size = sizeof(stai_module_info);
    int ret = staiFindModuleByLibraryNid(library_nid, &module_info);
    if(ret < 0) {
        return ret;
    }
    return module_info.module_uid;
}

char pem_buf[0x8000];

void load_ca_certs() {
    char filename[128];

    SceUID dfd = sceIoDopen(custom_ca_dir);
    if(dfd < 0) {
        LOG("dopen(%s): %08x\n", custom_ca_dir, dfd);
        return;
    }
    while(1) {
        SceIoDirent ent;
        int ret = sceIoDread(dfd, &ent);
        if(ret <= 0) {
            break;
        }

        size_t buf_size = ent.d_stat.st_size;
        if(buf_size > sizeof(pem_buf)) {
            LOG("%s too big\n", filename);
            continue;
        }

        sceClibStrncpy(filename, custom_ca_dir, sizeof(filename));
        sceClibStrncat(filename, ent.d_name, sizeof(filename) - sceClibStrnlen(custom_ca_dir, sizeof(filename)) - 1);
        SceUID ffd = sceIoOpen(filename, SCE_O_RDONLY, 0666);
        if(ffd < 0) {
            LOG("open(%s): %08x\n", filename, ffd);
            continue;
        }
        ret = sceIoRead(ffd, pem_buf, buf_size);
        if(ret < 0) {
            sceIoClose(ffd);
            LOG("read(%s): %08x\n", filename, ret);
            continue;
        }
        sceIoClose(ffd);

        SceHttpsData data = {
            .ptr = pem_buf,
            .size = buf_size
        };
        const SceHttpsData* caList = {&data};
        ret = sceHttpsLoadCert(1, &caList, NULL, NULL);
        if(ret < 0) {
            LOG("sceHttpsLoadCert(%s): %08x\n", filename, ret);
            continue;
        }
        LOG("loaded ca cert: %s\n", filename);
    }
    sceIoDclose(dfd);
}

STAI_HOOK(int, sceHttpInit, unsigned int poolSize) {
    int ret = STAI_HOOK_CONTINUE(sceHttpInit, poolSize);
    if(ret < 0) {
        return ret;
    }
    load_ca_certs();
    return ret;
}

STAI_HOOK(int, SceHttp_module_start, SceSize argc, void* argv) {
    int ret = STAI_HOOK_CONTINUE(SceHttp_module_start, argc, argv);
    if(ret != SCE_KERNEL_START_SUCCESS) {
        return ret;
    }
    SceUID module_uid = module_uid_by_library_nid(SceHttp_library_nid);
    if(module_uid < 0) {
        LOG("module_uid_by_library_nid: %08x\n", module_uid);
        return SCE_KERNEL_START_SUCCESS;
    }
    ret = staiHookExport(module_uid, SceHttp_library_nid, 0x214926D9, sceHttpInit_hook, &sceHttpInit_hook_ref);
    if(ret < 0) {
        LOG("staiHookExport(sceHttpInit): %08x\n", ret);
    }
    return SCE_KERNEL_START_SUCCESS;
}

int module_start(SceSize argc, void* argv) {
    int ret = staiHookModuleStart(SceHttp_library_nid, SceHttp_module_start_hook, &SceHttp_module_start_hook_ref);
    LOG("staiHookModuleStart(SceHttp): %08x\n", ret);
    return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, void* argv) {
    return SCE_KERNEL_STOP_SUCCESS;
}
