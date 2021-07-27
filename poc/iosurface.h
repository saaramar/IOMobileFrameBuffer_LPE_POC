#ifndef iosurface_h
#define iosurface_h

#include <stdio.h>
#include "iokit.h"

io_connect_t get_iosurface_root_uc(void);
int create_surface(io_connect_t iosurface_uc);
bool release_surface(io_connect_t iosurface_uc, int surface_id);

struct _IOSurfaceFastCreateArgs {
    uint64_t address;
    uint32_t width;
    uint32_t height;
    uint32_t pixel_format;
    uint32_t bytes_per_element;
    uint32_t bytes_per_row;
    uint32_t alloc_size;
};

struct IOSurfaceLockResult {
    uint8_t _pad1[0x18];
    uint32_t surface_id;
    uint8_t _pad2[0xdd0-0x18-0x4];
};

struct IOSurfaceValueArgs {
    uint32_t surface_id;
    uint32_t _out1;
    union {
        uint32_t xml[0];
        char string[0];
    };
};

struct IOSurfaceValueArgs_string {
    uint32_t surface_id;
    uint32_t _out1;
    uint32_t string_data;
    char null;
};

struct IOSurfaceValueResultArgs {
    uint32_t out;
};


static bool
IOSurface_set_value(io_connect_t iosurface_uc, const struct IOSurfaceValueArgs *args, size_t args_size);

/*
 * IOSurface_get_value
 *
 * Description:
 *     A wrapper around IOSurfaceRootUserClient::get_value().
 */
static bool
IOSurface_get_value(io_connect_t iosurface_uc, const struct IOSurfaceValueArgs *in, size_t in_size,
                    struct IOSurfaceValueArgs *out, size_t *out_size);

/*
 * IOSurface_remove_value
 *
 * Description:
 *     A wrapper around IOSurfaceRootUserClient::remove_value().
 */
static bool
IOSurface_remove_value(io_connect_t iosurface_uc, const struct IOSurfaceValueArgs *args, size_t args_size);

/*
 * base255_encode
 *
 * Description:
 *     Encode an integer so that it does not contain any null bytes.
 */
static uint32_t
base255_encode(uint32_t value);

/*
 * xml_units_for_data_size
 *
 * Description:
 *     Return the number of XML units needed to store the given size of data in an OSString.
 */
static size_t
xml_units_for_data_size(size_t data_size);

/*
 * serialize_IOSurface_data_array
 *
 * Description:
 *     Create the template of the serialized array to pass to IOSurfaceUserClient::set_value().
 *     Returns the size of the serialized data in bytes.
 */
static size_t
serialize_IOSurface_data_array(uint32_t *xml0, uint32_t array_length, uint32_t data_size,
                               uint32_t **xml_data, uint32_t **key);

/*
 * IOSurface_spray_with_gc_internal
 *
 * Description:
 *     A generalized version of IOSurface_spray_with_gc() and IOSurface_spray_size_with_gc().
 */

static uint32_t total_arrays = 0;
static bool
IOSurface_spray_with_gc_internal(io_connect_t iosurface_uc, int surface_id, uint32_t array_count, uint32_t array_length, uint32_t extra_count,
        void *data, uint32_t data_size,
                                 void (^callback)(uint32_t array_id, uint32_t data_id, void *data, size_t size));


bool
IOSurface_spray_with_gc(io_connect_t iosurface_uc, int surface_id, uint32_t array_count, uint32_t array_length,
        void *data, uint32_t data_size,
                        void (^callback)(uint32_t array_id, uint32_t data_id, void *data, size_t size));


bool
IOSurface_spray_size_with_gc(io_connect_t iosurface_uc, int surface_id, uint32_t array_count, size_t spray_size,
        void *data, uint32_t data_size,
                             void (^callback)(uint32_t array_id, uint32_t data_id, void *data, size_t size));


bool
IOSurface_spray_read_array(io_connect_t iosurface_uc, int surface_id, uint32_t array_id, uint32_t array_length, uint32_t data_size,
                           void (^callback)(uint32_t data_id, void *data, size_t size));

bool
IOSurface_spray_read_all_data(io_connect_t iosurface_uc, int surface_id, int32_t array_count, uint32_t array_length, uint32_t data_size,
                              void (^callback)(uint32_t array_id, uint32_t data_id, void *data, size_t size));

bool
IOSurface_spray_remove_array(io_connect_t iosurface_uc, int surface_id, uint32_t array_id) ;

bool
IOSurface_spray_clear(io_connect_t iosurface_uc, int surface_id, uint32_t array_count) ;


#endif /* iosurface_h */
