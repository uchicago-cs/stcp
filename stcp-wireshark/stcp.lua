-- Quick and dirty STCP dissector for Wireshark
-- Written by: Borja Sotomayor
do
	require("bit")

	FL_URG = 0x20
	FL_ACK = 0x10
	FL_PSH = 0x08
	FL_RST = 0x04
	FL_SYN = 0x02
	FL_FIN = 0x01

	local stcp = Proto("stcp", "Simple Transmission Control Protocol")

	function stcp.init()
	end

	local f = stcp.fields
	f.srcprt = ProtoField.uint16("stcp.srcprt", "Source port")
	f.dstprt = ProtoField.uint16("stcp.dstprt", "Destination port")
	f.seq = ProtoField.uint32("stcp.seq", "Sequence number")
	f.ack = ProtoField.uint32("stcp.ack", "Acknowledgement number")
	f.offset = ProtoField.uint8("stcp.offset", "Header length", base.DEC, nil, 0xF0)
	f.wsize = ProtoField.uint16("stcp.wsize", "Window size")
	f.len = ProtoField.uint16("stcp.len", "Payload length")
	f.data = ProtoField.bytes("stcp.data", "Payload")

	f.flurg = ProtoField.uint8("stcp.flurg", "URG", base.HEX, nil, FL_URG)
	f.flack = ProtoField.uint8("stcp.flack", "ACK", base.HEX, nil, FL_ACK)
	f.flpsh = ProtoField.uint8("stcp.flpsh", "PSH", base.HEX, nil, FL_PSH)
	f.flrst = ProtoField.uint8("stcp.flrst", "RST", base.HEX, nil, FL_RST)
	f.flsyn = ProtoField.uint8("stcp.flsyn", "SYN", base.HEX, nil, FL_SYN)
	f.flfin = ProtoField.uint8("stcp.flfin", "FIN", base.HEX, nil, FL_FIN)

	function stcp.dissector(buffer, pinfo, tree)
		if buffer:len() >= 20 then
			local subtree = tree:add(stcp, buffer())

			local srcprt = buffer(0, 2):uint()
			local dstprt = buffer(2, 2):uint()
			local seq = buffer(4, 4):uint()
			local ack = buffer(8, 4):uint()
			local offset = buffer(12, 1):uint()
			local hdrlen = bit.rshift(offset,4) * 4
			local flags = buffer(13, 1):uint()
			local wsize = buffer(14, 2):uint()
			local data = buffer(20)
			local len = buffer:len() - hdrlen

			subtree:add(f.srcprt, srcprt)
			subtree:add(f.dstprt, dstprt)
			subtree:add(f.seq, seq)
			subtree:add(f.ack, ack)
			local toffset = subtree:add(f.offset, offset)
			toffset:append_text(" (".. hdrlen .. " bytes)")

			subtree:add(f.flurg, flags)
			subtree:add(f.flack, flags)
			subtree:add(f.flpsh, flags)
			subtree:add(f.flrst, flags)
			subtree:add(f.flsyn, flags)
			subtree:add(f.flfin, flags)

			subtree:add(f.len, len)
			if len ~= 0 then
				subtree:add(f.data, data)
			end

			local info = srcprt .. " > " .. dstprt .. " [ "
			if bit.band(flags, FL_URG) == FL_URG then
				info = info .. "URG "
			end
			if bit.band(flags, FL_ACK) == FL_ACK then
				info = info .. "ACK "
			end
			if bit.band(flags, FL_PSH) == FL_PSH then
				info = info .. "PSH "
			end
			if bit.band(flags, FL_RST) == FL_RST then
				info = info .. "RST "
			end
			if bit.band(flags, FL_SYN) == FL_SYN then
				info = info .. "SYN "
			end
			if bit.band(flags, FL_FIN) == FL_FIN then
				info = info .. "FIN "
			end
			info = info .. "]"
			info = info .. " Seq=" .. seq 
			info = info .. " Ack=" .. ack 
			info = info .. " Win=" .. wsize
			info = info .. " Len=" .. len

			pinfo.cols.protocol = stcp.name
			pinfo.cols.info = info
		end
	end

	local tcp_table = DissectorTable.get("tcp.port")
	tcp_table:add(23300, stcp)
end
