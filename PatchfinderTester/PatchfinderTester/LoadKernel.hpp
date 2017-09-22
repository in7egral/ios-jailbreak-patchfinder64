//
//  LoadKernel.hpp
//  PatchfinderTester
//
//  Created by Vladimir Putin on 26.01.17.
//  Copyright © 2017 FriedApple Team. All rights reserved.
//

#ifndef LoadKernel_hpp
#define LoadKernel_hpp

#include <stdio.h>
#include <string>
#include <cstdio>
#include <fstream>
#include <vector>

#include <mach-o/loader.h>

typedef struct {
    uint64_t vmaddr;
    uint64_t fileoff;
    uint64_t filesize;
    uint64_t vmsize;
    std::string segment_name;
    uint8_t *segment_data;
} macho_segment;

typedef uint64_t (*locatePatchOffset) (uint64_t kernel_base, uint8_t *kernel_data, size_t kernel_size);

class LoadKernel {
public:
    LoadKernel();
    ~LoadKernel();
    bool loadKernel(const std::string &path);
    std::string getXnuVersion() const;
    bool locatePatchLocation(uint64_t &offset, locatePatchOffset callback);
    size_t getKernelVirtualBase() const;
    size_t getKernelVirtualSize() const;
    
private:
    void createKernel();
    bool addSegment(struct segment_command_64 *segment);
    bool parseKernel();
    void onError(const std::string &errMessage);

private:
    uint64_t m_kernel_virtual_base;
    size_t m_kernel_virtual_size;
    size_t m_kernel_file_size;
    uint8_t *m_kernel_data;
    std::string m_xnu_version;
    std::vector<macho_segment> m_segments;
    std::ifstream m_ifs;
};

#endif /* LoadKernel_hpp */
