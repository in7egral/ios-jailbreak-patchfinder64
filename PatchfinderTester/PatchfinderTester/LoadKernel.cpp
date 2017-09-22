//
//  LoadKernel.cpp
//  PatchfinderTester
//
//  Created by Vladimir Putin on 26.01.17.
//  Copyright © 2017 FriedApple Team. All rights reserved.
//

#include "LoadKernel.hpp"
#include "log.hpp"

LoadKernel::LoadKernel() :
m_kernel_virtual_base(0),
m_kernel_virtual_size(0),
m_kernel_file_size(0),
m_kernel_data(0)
{
    // nothing here
}

LoadKernel::~LoadKernel()
{
    if (!m_segments.empty()) {
        for (size_t i = 0; i < m_segments.size(); ++i) {
            delete m_segments.at(i).segment_data;
            m_segments[i].segment_data = 0;
        }
        m_segments.clear();
    }
    delete[] m_kernel_data;
}

bool LoadKernel::loadKernel(const std::string &path)
{
    // open file
    m_ifs.open(path, std::ios::binary | std::ios::in);
    
    if (!m_ifs.is_open()) {
        onError("Can't open specified path " + path);
        return false;
    }
    
    return parseKernel();
}


std::string LoadKernel::getXnuVersion() const
{
    return m_xnu_version;
}

bool LoadKernel::locatePatchLocation(uint64_t &offset, locatePatchOffset callback)
{
    // use callback to test patchdinder
    if (m_segments.empty()) {
        onError("No segments loaded...");
        return false;
    }
    
    bool isFound = false;
    // call callback
    uint64_t new_offset = callback(m_kernel_virtual_base, m_kernel_data, m_kernel_virtual_size);
    
    if (new_offset) {
        if (isFound) {
            consoleLog("WARNING: another location found!");
        } else {
            // save first value only
            offset = new_offset;
        }
        isFound = true;
    }

    return isFound;
}

size_t LoadKernel::getKernelVirtualBase() const
{
    return m_kernel_virtual_base;
}

size_t LoadKernel::getKernelVirtualSize() const
{
    return m_kernel_virtual_size;
}

void LoadKernel::onError(const std::string &errMessage)
{
    if (m_ifs.is_open())
        m_ifs.close();
    consoleLog(errMessage);
}

void LoadKernel::createKernel()
{
    // allocate buffer
    m_kernel_data = new uint8_t[m_kernel_virtual_size];
    
    // create kernel from all segments
    for (size_t iSegment = 0; iSegment < m_segments.size(); ++ iSegment) {
        macho_segment &segment = m_segments.at(iSegment);
        uint64_t base_offset = segment.vmaddr - m_kernel_virtual_base;
        if (segment.filesize) {
            memcpy(m_kernel_data + base_offset, segment.segment_data, segment.filesize);
        }
        if (segment.filesize < segment.vmsize) {
            memset(m_kernel_data + base_offset + segment.filesize, 0, segment.vmsize - segment.filesize);
        }
    }
    
    // extract xnu version
    const char xnu_version_magic[] = "root:xnu-";
    const char *ptr = (char *)memmem(m_kernel_data, m_kernel_virtual_size, xnu_version_magic, sizeof(xnu_version_magic)/sizeof(xnu_version_magic[0]));
    if (ptr) {
        while (*(--ptr) != 0);
        ++ptr;
        char xnu_version[512];
        strcpy(xnu_version, ptr);
        m_xnu_version = xnu_version;
    }
}

bool LoadKernel::addSegment(struct segment_command_64 *segment)
{
    macho_segment newSegment;
    
    // get segment name
    std::string segment_name = segment->segname;
    consoleLog("addSegment: " + segment_name);
    
    // prepare segment info
    newSegment.segment_name = segment_name;
    newSegment.vmaddr = segment->vmaddr;
    newSegment.fileoff = segment->fileoff;
    newSegment.filesize = segment->filesize;
    newSegment.vmsize = segment->vmsize;
    
    if (newSegment.filesize) {
        // allocate buffer
        newSegment.segment_data = new uint8_t[newSegment.filesize];
        
        if (!newSegment.segment_data) {
            onError("can't allocate buffer for segment data");
            return false;
        }
        
        m_ifs.seekg(newSegment.fileoff, std::ios::beg);
        
        m_ifs.read((char *)newSegment.segment_data, newSegment.filesize);
        
        if (m_ifs.fail()) {
            onError("can't read segment data, invalid dump?");
            return false;
        }
    }
    else {
        newSegment.segment_data = 0;
    }
    
    m_segments.push_back(newSegment);
    
    return true;
}

bool LoadKernel::parseKernel()
{
    // parse macho
    const uint64_t header_size = sizeof(mach_header_64);
    char *buffer = new char[header_size];
    m_ifs.read(buffer, header_size);
    
    if (m_ifs.fail()) {
        onError("can't read mach_header_64");
        return false;
    }
    
    struct mach_header_64 *header = (struct mach_header_64 *)buffer;
    
    if (header->magic != MH_MAGIC_64) {
        onError("This is not MACH-o 64");
        return false;
    }
    
    uint32_t commands_count = header->ncmds;
    uint64_t commands_size = header->sizeofcmds;
    
    consoleLog("count of load_commands " + std::to_string(commands_count));
    
    delete[] buffer;
    
    buffer = new char[commands_size];
    
    m_ifs.read(buffer, commands_size);
    
    if (m_ifs.fail()) {
        onError("can't read load_commands");
        return false;
    }
    
    uint64_t minimum_kernel_va = -1;
    uint64_t maximum_kernel_va = 0;
    size_t kernel_file_size = 0;
    size_t total_kernel_size = 0;
    
    struct load_command *lc = (struct load_command *)buffer;
    bool isErr = false;
    
    for (uint32_t iCmd = 0; iCmd < commands_count; ++iCmd) {
        if (lc->cmd == LC_SEGMENT_64) {
            // load segment
            //consoleLog("loading command #" + std::to_string(iCmd) + "...");
            struct segment_command_64 *segment = (struct segment_command_64 *)lc;
            
            if (!addSegment(segment)) {
                onError("can't load command #" + std::to_string(iCmd));
                isErr = true;
                break;
            }
            if (segment->vmaddr < minimum_kernel_va) {
                minimum_kernel_va = segment->vmaddr;
            }
            if (segment->vmaddr + segment->vmsize > maximum_kernel_va) {
                maximum_kernel_va = segment->vmaddr + segment->vmsize;
            }
            kernel_file_size += segment->filesize;
        }
        // next command
        lc = (struct load_command *) ((char *)lc + lc->cmdsize);
    }
    
    delete[] buffer;
    
    if (isErr) {
        onError("kernel load failed");
        return false;
    }
    
    total_kernel_size = maximum_kernel_va - minimum_kernel_va;
    
    m_kernel_virtual_base = minimum_kernel_va;
    m_kernel_virtual_size = total_kernel_size;
    m_kernel_file_size = kernel_file_size;
    
    createKernel();
    
    return true;
}
