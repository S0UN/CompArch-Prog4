typedef struct {
    unsigned int file_type;      // Always 0 for now.
    unsigned int code_seg_begin; // For this project, code loads at 0x2000.
    unsigned int code_seg_size;  // In bytes.
    unsigned int data_seg_begin; // For this project, data loads at 0x10000.
    unsigned int data_seg_size;  // In bytes.
} TinkerFileHeader;
