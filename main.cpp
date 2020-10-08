#include <iostream>
#include <cstring>
#ifdef __linux__
#include <arpa/inet.h>
#elif _WIN32
#include <winsock2.h>
#endif
#include "utils.h"

#if 0
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

struct _KZB_root_folder_header {
    uint16_t name_sz;
    uint8_t  name[name_sz];
    uint32_t unk1;
    uint32_t unk2;
    uint32_t unk3;
    uint32_t zero;
    uint32_t count;
};

#pragma pack(pop)
#endif

using namespace std;

const char FZBF_sign[5] = "KZBF";

struct KZB_Root_Folder {
    uint32_t count;
    std::string name;
    uint32_t unk1;
    uint32_t unk2;
    uint32_t unk3;
};

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
fs::path G_extract_path;
int G_idx = 0x4c;
std::vector<uint8_t> G_bin;


void extract_resource(const fs::path &resource_path, uint32_t address, uint32_t size) {

    auto unk = *(uint32_t*)&G_bin[address];
//    if(unk) { TODO:
//        printf("%s - 0x%x(%d)\n", resource_name.c_str(), unk, unk);
//        throw std::runtime_error("Res unk !=0 ");
//    }
    FTUtils::bufferToFile(G_extract_path / resource_path, (const char*)&G_bin[address + sizeof(uint32_t)], size);
}

uint32_t parseElements(const fs::path &prefix, unsigned count, int depth) {

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

        uint16_t str_sz = ntohs(*(uint16_t*)&G_bin[G_idx]);
        G_idx+=sizeof(uint16_t);
        char* str = new char[str_sz + 1];
        str[str_sz] = 0;
        memcpy(str, (uint8_t*)&G_bin[G_idx], str_sz);
        element.name = str;
        delete[] str;
        G_idx+=str_sz;
        G_idx = (G_idx % 4) ? (G_idx / 4 + 1) * 4 : G_idx; //align
#if _WIN32
        auto file_path = fs::path(prefix) / FTUtils::normalize_path(element.name);
#else
        auto file_path = fs::path(prefix) / element.name;
#endif
        for(int j = 0; j < depth; ++j)
            printf("\t");
        printf("File: %s Size: 0x%x(%d) Addr: 0x%x(%d) Unk1: 0x%x(%d) Unk2: 0x%x(%d)\n",
               element.name.c_str(),
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

uint32_t parseFolder(const fs::path &prefix, int depth) {

    KZB_Folder folder = {};

    folder.size = ntohl(*(uint32_t*)&G_bin[G_idx]);
    G_idx+=sizeof(uint32_t);

    uint16_t str_sz = ntohs(*(uint16_t*)&G_bin[G_idx]);
    G_idx+=sizeof(uint16_t);

    char* str = new char[str_sz + 1];
    str[str_sz] = 0;
    memcpy(str, (uint8_t*)&G_bin[G_idx], str_sz);
    folder.name = str;
    delete[] str;
    G_idx+=str_sz;
    G_idx = (G_idx % 4) ? (G_idx / 4 + 1) * 4 : G_idx; //align

    folder.count = ntohl(*(uint32_t*)&G_bin[G_idx]);
    G_idx+=sizeof(uint32_t);

    bool last_folder = (folder.count == 0);
    if(last_folder) {
        folder.count = ntohl(*(uint32_t*)&G_bin[G_idx]);
        G_idx+=sizeof(uint32_t);
    }

    auto folder_path = prefix / ("Folder_"+folder.name);

    for(int i = 0; i < depth; ++i)
        printf("\t");
    printf("Folder: %s Size: 0x%x(%d) Count: 0x%x(%d)\n",
           folder.name.c_str(),
           folder.size, folder.size,
           folder.count, folder.count);

    if(G_extract) {
        fs::create_directory(G_extract_path / folder_path);
    }

    uint32_t processed_size = 0;
    if(last_folder) {
        parseElements(folder_path, folder.count, depth+1);
    } else {
        for (int i =0; i < folder.count; ++i) {
            processed_size += parseFolder(folder_path, depth+1);
        }
        if(processed_size != folder.size) {
            uint32_t elem_count = ntohl(*(uint32_t*)&G_bin[G_idx]);
            G_idx+=sizeof(uint32_t);

            parseElements(folder_path, elem_count,depth+1);
        }
    }

    return folder.size;
}

void parse_kzb(const fs::path &in_file) {

    G_idx = 0x4c;

    KZB_Root_Folder rootFolder;

    uint16_t str_sz = ntohs(*(uint16_t*)&G_bin[G_idx]);
    G_idx+=sizeof(uint16_t);
    char* str = new char[str_sz + 1];
    str[str_sz] = 0;
    memcpy(str, (uint8_t*)&G_bin[G_idx], str_sz);
    rootFolder.name = str;
    delete[] str;
    G_idx+=str_sz;
    G_idx = (G_idx % 4) ? (G_idx / 4 + 1) * 4 : G_idx; //align

    rootFolder.unk1 = ntohl(*(uint32_t*)&G_bin[G_idx]);
    G_idx+=sizeof(uint32_t);

    rootFolder.unk2 = ntohl(*(uint32_t*)&G_bin[G_idx]);
    G_idx+=sizeof(uint32_t);

    rootFolder.unk3 = ntohl(*(uint32_t*)&G_bin[G_idx]);
    G_idx+=sizeof(uint32_t);

    auto zero = ntohl(*(uint32_t*)&G_bin[G_idx]);
    G_idx+=sizeof(uint32_t);

    rootFolder.count = ntohl(*(uint32_t*)&G_bin[G_idx]);
    G_idx+=sizeof(uint32_t);

    printf("%s:\n", rootFolder.name.c_str());
    for(int i =0; i < rootFolder.count; ++i)
        parseFolder("", 1);

    printf("0x%x", G_idx);
}

#pragma pack(push, 1)
struct KZBF_elem {
    uint32_t idx;
    uint32_t unk1; //FFS?
    uint32_t addr;
    uint32_t size;
    uint32_t unk4; //always zero
    uint32_t unk5; //duplicate sz
};
#pragma pack(pop)

void extract_resource_kzbf(const fs::path &resource_path, uint32_t address, uint32_t size) {

    auto path = G_extract_path; path += resource_path;
    fs::create_directories(path.parent_path());
    FTUtils::bufferToFile(path, (const char*)&G_bin[address], size);
}

void parse_kzbf(const fs::path &in_file) {

    auto unk = *(uint32_t*)&G_bin[G_idx];
    G_idx += sizeof(uint32_t);

    /*Parse first section*/
    auto str_sz = *(uint32_t*)&G_bin[G_idx];
    G_idx += sizeof(uint32_t);
    char* str = new char[str_sz + 1];
    str[str_sz] = 0;
    memcpy(str, (uint8_t*)&G_bin[G_idx], str_sz);
    G_idx += str_sz;
    string rootName(str);
    delete[] str;

    auto count = *(uint32_t*)&G_bin[G_idx];
    G_idx += sizeof(uint32_t);

    vector<string> nodes(count);
    for(int i = 0; i < count; ++i) {
        while (G_bin[G_idx]) {
            nodes[i] = string((char*)&G_bin[G_idx]);
            G_idx += nodes[i].size();
        }
        G_idx++;
    }

    printf("Nodes count: %ld\n", nodes.size());

    /* Parse props */
    count = *(uint32_t*)&G_bin[G_idx];
    G_idx += sizeof(uint32_t);

    vector<KZBF_elem> elems(count);
    for(int i = 0; i < count; ++i) {
        elems[i] = *(KZBF_elem*)&G_bin[G_idx];
        G_idx += sizeof(KZBF_elem);
    }

    printf("Nodes prop count: %ld\n", nodes.size());

    for(int i = 0; i < nodes.size(); ++i)
        printf("%04d 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x %s\n",
               elems[i].idx,
               elems[i].unk1,
               elems[i].addr,
               elems[i].size,
               elems[i].unk4,
               elems[i].unk5,
               nodes[i].c_str());
    //TODO: add check if unk5 != size
    //TODO: add check if unk4 != 0

    /* extract pics */
    for(int i = 0; i < nodes.size(); ++i) {
        const auto &_node = nodes[i];
        if (_node.find(".png") != std::string::npos) {
            auto res_sz = elems[i].size;
            G_idx = elems[i].addr;

            auto unk1 = *(uint32_t*)&G_bin[G_idx];
            G_idx += sizeof(uint32_t);

            auto unk2 = *(uint32_t*)&G_bin[G_idx];
            G_idx += sizeof(uint32_t);

            auto unk3 = *(uint32_t*)&G_bin[G_idx];
            G_idx += sizeof(uint32_t);

            auto unk4 = *(uint32_t*)&G_bin[G_idx];
            G_idx += sizeof(uint32_t);

            auto unk5 = *(uint32_t*)&G_bin[G_idx];
            G_idx += sizeof(uint32_t);

            //resource
            if(G_extract) {
                extract_resource_kzbf(_node, G_idx, res_sz - (5 * sizeof(uint32_t)));
            }
        }
    }
}

int main(int argc, const char* argv[]) {

    if(argc <= 1) {
        std::cerr << "Provide .kzb file" << std::endl;
        return 0;
    }

    fs::path in_file(argv[1]);
    G_extract_path = in_file.parent_path()/(in_file.filename().string()+"_unpacked");
    fs::create_directory(G_extract_path);

    G_idx = 0;
    G_bin = FTUtils::fileToVector(in_file);

    char sign[5] = {};
    sign[0] = G_bin[G_idx + 0];
    sign[1] = G_bin[G_idx + 1];
    sign[2] = G_bin[G_idx + 2];
    sign[3] = G_bin[G_idx + 3];
    G_idx += sizeof(uint32_t);

    if(strcmp(sign,FZBF_sign) != 0)
        parse_kzb(in_file);
    else
        parse_kzbf(in_file);

    return 0;
}
