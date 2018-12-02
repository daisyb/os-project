#include "frame.h"

void swap_init (void);
bool swap_in (struct page *p);
bool swap_out (struct page *p);
void swap_free_slot(size_t swap_index);
