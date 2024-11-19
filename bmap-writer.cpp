/*
 * (C) Copyright 2024
 * Embetrix Embedded Systems Solutions, ayoub.zaki@embetrix.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 3 of
 * the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <openssl/evp.h>

#define CHECKSUM_LENGTH 64
#define RANGE_LENGTH 19

struct Range {
    std::string checksum;
    std::string range;
};

struct bmap_t {
    std::vector<Range> ranges;
    int blockSize;
};

bmap_t parseBMap(const std::string &filename) {
    bmap_t bmapData;
    bmapData.blockSize = 0;

    xmlDocPtr doc = xmlReadFile(filename.c_str(), NULL, 0);
    if (doc == NULL) {
        std::cerr << "Failed to parse " << filename << std::endl;
        exit(EXIT_FAILURE);
    }

    xmlNodePtr root_element = xmlDocGetRootElement(doc);
    for (xmlNodePtr node = root_element->children; node; node = node->next) {
        if (node->type == XML_ELEMENT_NODE) {
            if (strcmp((const char *)node->name, "BlockSize") == 0) {
                xmlChar *blockSizeStr = xmlNodeGetContent(node);
                bmapData.blockSize = std::stoi((const char *)blockSizeStr);
                xmlFree(blockSizeStr);
                std::cout << "Parsed BlockSize: " << bmapData.blockSize << std::endl;
            } else if (strcmp((const char *)node->name, "BlockMap") == 0) {
                for (xmlNodePtr rangeNode = node->children; rangeNode; rangeNode = rangeNode->next) {
                    if (rangeNode->type == XML_ELEMENT_NODE && strcmp((const char *)rangeNode->name, "Range") == 0) {
                        xmlChar *checksum = xmlGetProp(rangeNode, (const xmlChar *)"chksum");
                        xmlChar *range = xmlNodeGetContent(rangeNode);

                        Range r;
                        r.checksum = (const char *)checksum;
                        r.range = (const char *)range;

                        bmapData.ranges.push_back(r);

                        std::cout << "Parsed Range: checksum=" << r.checksum << ", range=" << r.range << std::endl;

                        xmlFree(checksum);
                        xmlFree(range);
                    }
                }
            }
        }
    }

    xmlFreeDoc(doc);
    xmlCleanupParser();

    return bmapData;
}

void computeSHA256(const char *buffer, size_t size, char *output) {
    EVP_MD_CTX *mdctx;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, buffer, size);
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);

    for (unsigned int i = 0; i < hash_len; ++i) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[CHECKSUM_LENGTH] = 0;
}

bool isCompressed(const std::string &imageFile) {
    std::ifstream file(imageFile, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open image file" << std::endl;
        return false;
    }

    unsigned char buffer[2];
    file.read(reinterpret_cast<char*>(buffer), 2);
    file.close();

    // Check for gzip magic number
    return buffer[0] == 0x1f && buffer[1] == 0x8b;
}

bool isDeviceMounted(const std::string &device) {
    std::ifstream mounts("/proc/mounts");
    std::string line;
    while (std::getline(mounts, line)) {
        if (line.find(device) != std::string::npos) {
            return true;
        }
    }
    return false;
}

void printBufferHex(const char *buffer, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        printf("%02x", (unsigned char)buffer[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        } else {
            printf(" ");
        }
    }
    printf("\n");
}

void BmapWriteImage(const std::string &imageFile, const bmap_t &bmap, const std::string &device) {
    int dev_fd = open(device.c_str(), O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
    if (dev_fd < 0) {
        perror("Unable to open or create target device");
        return;
    }

    std::ifstream img(imageFile, std::ios::binary);
    if (!img) {
        perror("Unable to open image file");
        close(dev_fd);
        return;
    }

    for (const auto &range : bmap.ranges) {
        int startBlock, endBlock;
        if (sscanf(range.range.c_str(), "%d-%d", &startBlock, &endBlock) == 1) {
            endBlock = startBlock;  // Handle single block range
        }
        std::cout << "Processing Range: startBlock=" << startBlock << ", endBlock=" << endBlock << std::endl;

        img.seekg(startBlock * bmap.blockSize, std::ios::beg);
        size_t bufferSize = (endBlock - startBlock + 1) * bmap.blockSize;
        std::vector<char> buffer(bufferSize);
        img.read(buffer.data(), bufferSize);
        size_t bytesRead = img.gcount();
        if (bytesRead == 0 && img.fail()) {
            perror("Failed to read from image file");
            close(dev_fd);
            return;
        }

        // Compute and verify the checksum
        char computedChecksum[CHECKSUM_LENGTH + 1];
        computeSHA256(buffer.data(), bytesRead, computedChecksum);
        std::cout << "Computed Checksum: " << computedChecksum << std::endl;
        std::cout << "Expected Checksum: " << range.checksum << std::endl;
        if (strcmp(computedChecksum, range.checksum.c_str()) != 0) {
            std::cerr << "Checksum verification failed for range: " << range.range << std::endl;
            std::cout << "Buffer content (hex):" << std::endl;
            printBufferHex(buffer.data(), bytesRead);
            close(dev_fd);
            exit(EXIT_FAILURE);
        }

        if (pwrite(dev_fd, buffer.data(), bytesRead, startBlock * bmap.blockSize) < 0) {
            perror("Write to device failed");
            close(dev_fd);
            return;
        }
    }

    if (fsync(dev_fd) != 0) {
        perror("fsync failed after all writes");
    }

    close(dev_fd);
    std::cout << "Finished writing image to device." << std::endl;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <image-file> <bmap-file> <target-device>" << std::endl;
        return 1;
    }

    std::string imageFile    = argv[1];
    std::string bmapFile     = argv[2];
    std::string device       = argv[3];

    std::cout << "Starting BMap writer..." << std::endl;
    if (isDeviceMounted(device)) {
        std::cerr << "Error: Device " << device << " is mounted. Please unmount it before proceeding." << std::endl;
        return 1;
    }
    bmap_t bmap = parseBMap(bmapFile);
    if (bmap.blockSize == 0) {
        std::cerr << "BlockSize not found in BMAP file" << std::endl;
        return 1;
    }
    BmapWriteImage(imageFile, bmap, device);
    std::cout << "Process completed." << std::endl;

    return 0;
}
