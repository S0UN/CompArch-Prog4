typedef struct
{
    uint64_t file_type;      // Always 0 for now.
    uint64_t code_seg_begin; // For this project, code loads at 0x2000.
    uint64_t code_seg_size;  // In bytes.
    uint64_t data_seg_begin; // For this project, data loads at 0x10000.
    uint64_t data_seg_size;  // In bytes.
} TinkerFileHeader;
