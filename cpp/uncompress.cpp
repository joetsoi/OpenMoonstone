#include <algorithm>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>


template <class T>
void swap_endianness(T *objp) {
    unsigned char *memp = reinterpret_cast<unsigned char*>(objp);
    std::reverse(memp, memp + sizeof(T));
}


std::vector<unsigned char> extractFile(std::ifstream& file) {
	std::vector<unsigned char> extracted;
	unsigned short file_type, file_size;

	if(file){
		file.read(reinterpret_cast<char*>(&file_type), 2);
		swap_endianness(&file_type);
		//std::cout << file_type << std::endl;
		file.seekg(2, std::ios::cur);
		file.read(reinterpret_cast<char*>(&file_size), sizeof(int));
		swap_endianness(&file_size);
		//std::cout << file_size << std::endl;

		file.seekg(6+64, std::ios::beg);
		int offset = 0;
		while (offset < file_size) {
			unsigned char header;
			file.read(reinterpret_cast<char*>(&header), sizeof(char));
			++offset;

			unsigned short encoded;
			unsigned char unencoded;
			for (unsigned int mask = 0x80; mask !=  0; mask >>= 1) {
				if (header & mask) {
					file.read(reinterpret_cast<char*>(&encoded), sizeof(short));
					offset += 2;
					swap_endianness(&encoded);

					unsigned int count = 0x22 - ((encoded & 0xf800) >> 11);
					unsigned int copy_source = encoded & 0x7ff;

					auto copy_from = extracted.end() - copy_source;
                    std::vector<unsigned char> new_bytes;
                    if (copy_from + count <= extracted.end()) {
                        new_bytes.assign(copy_from, copy_from + count);
                    } else { 
					    new_bytes.assign(copy_from, extracted.end());
                        int overlapped_bytes = count - copy_source;
                        for (int i = 0; i < overlapped_bytes; ++i) {
                            new_bytes.push_back(new_bytes[i]);
                        }
                    }

					extracted.insert(extracted.end(), new_bytes.begin(),
									 new_bytes.end());


				} else {
					file.read(reinterpret_cast<char*>(&unencoded), sizeof(char));
					++offset;
					swap_endianness(&unencoded);
					extracted.push_back(unencoded);
				}
                if (offset >= file_size) {
                    break;
                }
			}
		}
	}
    return extracted;
};


std::vector<unsigned char> readTestFile(std::ifstream& file) {
    std::vector<unsigned char> fileContents(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );
    return fileContents;
}

int main() {
	std::ifstream file("MINDSCAP", std::ifstream::binary);
    std::vector<unsigned char> extracted = extractFile(file);
	//std::cout << "extracted size: " << extracted.size() << std::endl;

	std::ifstream testFile("mindscap_extract_1.bin", std::ifstream::binary);
    std::vector<unsigned char> test = readTestFile(testFile);
	//std::cout << "test extracted size: " << test.size() << std::endl;

       /*
    int counter = 0;
    std::cout << std::hex << counter << "\t";
	for (auto& i : extracted) {

        if (i < 0x10)
            std::cout << 0;
		std::cout << std::hex << +i << " ";
        ++counter;
        if (counter % 4 == 0) {
            std::cout << " ";

        }
        if (counter % 16 == 0) {
            std::cout << std::endl;
            std::cout << std::hex << counter << "\t";

        }

	}
    //*/
	return 0;
}
