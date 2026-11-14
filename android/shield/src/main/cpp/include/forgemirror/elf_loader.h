#pragma once

#include <cstddef>
#include <cstdint>

namespace forgemirror::elf {

struct Image;

/** Load an ET_DYN image from memory without the platform dynamic linker. */
Image *load(const uint8_t *data, size_t size, const char *name);

/** Resolve an exported symbol from a custom image. */
void *symbol(Image *image, const char *name);

bool is_image(const void *handle);

/** Returns true when the address is inside a custom-loaded image. */
bool contains(const void *address);

void close(Image *image);

}  // namespace forgemirror::elf
