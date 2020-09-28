#include <iostream>
#include <cstring>
#include <netinet/in.h>
#include "utils.h"

#pragma pack(push, 1)
struct _KZB_elem_header {
    uint32_t addr;
    uint32_t sz; //size in elements
    uint32_t unk1;
    uint32_t unk2;
    uint16_t name_sz;
    uint8_t  name[0];
};

struct _KZB_subfolder_header {
    uint32_t unk1;
    uint16_t name_sz;
    uint32_t sz;
};

struct _KZB_last_subfolder_header {
    uint32_t size;          //size in hex
    uint16_t name_sz;
    uint32_t zero2;
    uint32_t count;         //elems count
};
#pragma pack(pop)

struct KZB_Folder {
    uint32_t size;
    uint32_t count;
    std::string name;
};

struct KZB_Element {
    uint32_t addr;
    uint32_t size;
    uint32_t unk1;
    uint32_t unk2;
    std::string name;
};

bool G_extract = true;
int G_idx = 0x6c;
std::vector<uint8_t> G_bin;


void extract_resource(const std::string &resource_name, uint32_t address, uint32_t size) {

    auto unk = *(uint32_t*)&G_bin[address];
    if(unk) {
        printf("%s - %x(%d)\n", resource_name.c_str(), unk, unk);
//        throw std::runtime_error("Res unk !=0 ");
    }
    FTUtils::bufferToFile(resource_name, (const char*)&G_bin[address+sizeof(uint32_t)], size);
}

uint32_t parseElements(const std::string &prefix, unsigned count) {

    uint32_t processed_size = 0;

    for(int i =0; i < count; ++i) {

        KZB_Element element = {};

        element.addr = ntohl(*(uint32_t*)&G_bin[G_idx]);
        G_idx+=sizeof(uint32_t);

        element.size = ntohl(*(uint32_t*)&G_bin[G_idx]);
        G_idx+=sizeof(uint32_t);

        element.unk1 = ntohl(*(uint32_t*)&G_bin[G_idx]);
        G_idx+=sizeof(uint32_t);

        element.unk2 = ntohl(*(uint32_t*)&G_bin[G_idx]);
        G_idx+=sizeof(uint32_t);

        uint8_t str_sz = ntohs(*(uint16_t*)&G_bin[G_idx]);
        G_idx+=sizeof(uint16_t);
        char str[str_sz+1]; str[str_sz] = 0;
        memcpy(str, (uint8_t*)&G_bin[G_idx], str_sz);
        element.name = str;
        G_idx+=str_sz;
        G_idx = (G_idx % 4) ? (G_idx / 4 + 1) * 4 : G_idx; //align

        auto file_path = prefix+"/"+element.name;
        printf("File: %s Size: %x(%d) Addr: %x(%d) Unk1: %x(%d) Unk2: %x(%d)\n",
               file_path.c_str(),
               element.size, element.size,
               element.addr, element.addr,
               element.unk1, element.unk1,
               element.unk2, element.unk2);
//        processed_size += element.unk1; //TODO:

        if(G_extract) {
            extract_resource(file_path, element.addr, element.size);
        }
    }
    return processed_size;
}

uint32_t parseFolder(const std::string &prefix) {

    KZB_Folder folder = {};

    folder.size = ntohl(*(uint32_t*)&G_bin[G_idx]);
    G_idx+=sizeof(uint32_t);

    uint8_t str_sz = ntohs(*(uint16_t*)&G_bin[G_idx]);
    G_idx+=sizeof(uint16_t);

    char str[str_sz+1]; str[str_sz] = 0;
    memcpy(str, (uint8_t*)&G_bin[G_idx], str_sz);
    folder.name = str;
    G_idx+=str_sz;
    G_idx = (G_idx % 4) ? (G_idx / 4 + 1) * 4 : G_idx; //align

    folder.count = ntohl(*(uint32_t*)&G_bin[G_idx]);
    G_idx+=sizeof(uint32_t);

    bool last_folder = (folder.count == 0);
    if(last_folder) {
        folder.count = ntohl(*(uint32_t*)&G_bin[G_idx]);
        G_idx+=sizeof(uint32_t);
    }

    auto folder_path = prefix+"/Folder_"+folder.name;
    printf("Folder: %s Size: %x(%d) Count: %x(%d)\n",
           folder_path.c_str(),
           folder.size, folder.size,
           folder.count, folder.count);

    if(G_extract) {
        fs::create_directory(folder_path);
    }

    uint32_t processed_size = 0;
    if(last_folder) {
        parseElements(folder_path, folder.count);
    } else {
        for (int i =0; i < folder.count; ++i) {
            processed_size += parseFolder(folder_path);
        }
        if(processed_size != folder.size) {
            uint32_t elem_count = ntohl(*(uint32_t*)&G_bin[G_idx]);
            G_idx+=sizeof(uint32_t);

            parseElements(folder_path, elem_count);
        }
    }

    return folder.size;
}

int main() {

    G_bin = FTUtils::fileToVector("/home/user/bak/CLionProjects/KZB/cluster.kzb");

    for(int i =0; i < 0x11; ++i)
        parseFolder("./unpacked");

    printf("%x", G_idx);

    return 0;
}
