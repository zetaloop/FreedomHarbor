local versions = {
	[0x00000001] = {
		salt = "\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a",
		label = "quic",
		initial = 0,
		retry = 3,
	},
	[0x6b3343cf] = {
		salt = "\x0d\xed\xe3\xde\xf7\x00\xa6\xdb\x81\x93\x81\xbe\x6e\x26\x9d\xcb\xf9\xbd\x2e\xd9",
		label = "quicv2",
		initial = 1,
		retry = 0,
	},
}

local function varint(data, position)
	local value, size = quic_tvb(data, position)
	if size then return value, position + size end
end

local function words(value)
	if type(value) == "string" then
		return bitand(u32(value), 0x3fffffff), u32(value, 5)
	end
	return divint(value, 0x100000000), value % 0x100000000
end

local function advance(value, count)
	local high, low = words(value)
	low = low + count
	high = high + divint(low, 0x100000000)
	low = low % 0x100000000
	if high >= 0x40000000 then return end
	if high <= 0x1fffff then return high * 0x100000000 + low end
	return bu32(high + 0xc0000000) .. bu32(low)
end

local function compare(a, b)
	local ah, al = words(a)
	local bh, bl = words(b)
	if ah ~= bh then return ah < bh and -1 or 1 end
	if al ~= bl then return al < bl and -1 or 1 end
	return 0
end

local function label(name, length)
	name = "tls13 " .. name
	return bu16(length) .. bu8(#name) .. name .. "\0"
end

local function expand(secret, name, length)
	local key = secret .. string.rep("\0", 64 - #secret)
	local inner = hash("sha256", bxor(key, string.rep("\x36", 64)) .. label(name, length) .. "\1")
	return hash("sha256", bxor(key, string.rep("\x5c", 64)) .. inner):sub(1, length)
end

local function keys(version, dcid)
	local parameters = versions[version]
	local secret = hkdf("sha256", parameters.salt, dcid, label("client in", 32), 32)
	return {
		version = version,
		dcid = dcid,
		key = expand(secret, parameters.label .. " key", 16),
		iv = expand(secret, parameters.label .. " iv", 12),
		hp = expand(secret, parameters.label .. " hp", 16),
	}
end

local function header(data, start)
	local first = data:byte(start)
	if not first or bitand(first, 0x80) == 0 or start + 6 > #data then return end
	local version = u32(data, start + 1)
	local parameters = versions[version]
	if not parameters then return end
	local kind = bitand(bitrshift(first, 4), 3)
	if kind == parameters.retry then return end
	local position = start + 5
	local length = data:byte(position)
	if position + length + 1 > #data then return end
	local dcid = data:sub(position + 1, position + length)
	position = position + length + 1
	length = data:byte(position)
	if position + length >= #data then return end
	local scid = data:sub(position + 1, position + length)
	position = position + length + 1
	local initial = kind == parameters.initial
	if initial then
		length, position = varint(data, position)
		if type(length) ~= "number" then return end
		position = position + length
	end
	length, position = varint(data, position)
	if type(length) ~= "number" or position + length - 1 > #data then return end
	return {
		start = start,
		finish = position + length - 1,
		pn = position,
		version = version,
		dcid = dcid,
		scid = scid,
		initial = initial,
	}
end

local function decrypt(data, packet, state)
	if packet.pn + 19 > packet.finish then return end
	local mask = aes(true, state.hp, data:sub(packet.pn + 4, packet.pn + 19))
	local first = bitxor(data:byte(packet.start), bitand(mask:byte(1), 0x0f))
	if bitand(first, 0x0c) ~= 0 then return end
	local size = bitand(first, 3) + 1
	local pn = bxor(data:sub(packet.pn, packet.pn + size - 1), mask:sub(2, size + 1))
	local number = 0
	for index = 1, size do number = number * 256 + pn:byte(index) end
	local high = state.pn_high or 0
	local expected = (state.pn_low or -1) + 1
	if expected == 0x100000000 then high, expected = high + 1, 0 end
	local window = bitlshift(1, size * 8)
	local low = expected - expected % window + number
	if low + window / 2 <= expected and (high < 0x3fffffff or low + window < 0x100000000) then
		low = low + window
	elseif low > expected + window / 2 and (high > 0 or low >= window) then
		low = low - window
	end
	if low >= 0x100000000 then high, low = high + 1, low - 0x100000000 end
	if low < 0 then high, low = high - 1, low + 0x100000000 end
	if high < 0 or high >= 0x40000000 then return end
	local associated = string.char(first) .. data:sub(packet.start + 1, packet.pn - 1) .. pn
	local nonce = bxor(state.iv, string.rep("\0", 4) .. bu32(high) .. bu32(low))
	local plaintext, tag = aes_gcm(false, state.key, nonce, data:sub(packet.pn + size, packet.finish - 16), associated)
	if tag ~= data:sub(packet.finish - 15, packet.finish) then return end
	if not state.pn_high or high > state.pn_high or (high == state.pn_high and low > state.pn_low) then
		state.pn_high, state.pn_low = high, low
	end
	return plaintext, associated, nonce
end

local function frame(offset, data)
	return "\6" .. bquic_tvb(offset) .. bquic_tvb(#data) .. data
end

local function reframe(data)
	local ranges, output = {}, {}
	local position = 1
	while position <= #data do
		local start = position
		local kind
		kind, position = varint(data, position)
		if not kind or position ~= start + 1 then return end
		if kind == 0 then
			position = data:find("[^%z]", position) or #data + 1
		elseif kind == 1 then
			output[#output + 1] = "\1"
		elseif kind == 2 or kind == 3 then
			local value, count
			value, position = varint(data, position)
			if not value then return end
			value, position = varint(data, position)
			if not value then return end
			count, position = varint(data, position)
			if type(count) ~= "number" then return end
			value, position = varint(data, position)
			if not value then return end
			for _ = 1, count do
				value, position = varint(data, position)
				if not value then return end
				value, position = varint(data, position)
				if not value then return end
			end
			if kind == 3 then
				for _ = 1, 3 do
					value, position = varint(data, position)
					if not value then return end
				end
			end
			output[#output + 1] = data:sub(start, position - 1)
		elseif kind == 6 then
			local offset, length
			offset, position = varint(data, position)
			if not offset then return end
			length, position = varint(data, position)
			if type(length) ~= "number" or position + length - 1 > #data or not advance(offset, length) then return end
			if length == 0 then
				output[#output + 1] = data:sub(start, position - 1)
			else
				ranges[#ranges + 1] = { offset = offset, data = data:sub(position, position + length - 1) }
			end
			position = position + length
		else
			return
		end
	end
	if #ranges == 0 then return end
	table.sort(ranges, function(a, b) return compare(a.offset, b.offset) > 0 end)
	local available = #data - #table.concat(output)
	local previous
	for _, range in ipairs(ranges) do
		if previous and compare(advance(range.offset, #range.data), previous) > 0 then return end
		range.frame = frame(range.offset, range.data)
		available = available - #range.frame
		previous = range.offset
	end
	if available < 0 then return end
	for _, range in ipairs(ranges) do
		local encoded = range.frame
		if #range.data > 1 then
			local middle = divint(#range.data, 2)
			local split = frame(advance(range.offset, middle), range.data:sub(middle + 1))
				.. frame(range.offset, range.data:sub(1, middle))
			local extra = #split - #encoded
			if extra <= available then
				encoded = split
				available = available - extra
			end
		end
		output[#output + 1] = encoded
	end
	return table.concat(output) .. string.rep("\0", available)
end

local function rewrite(data, packet, cache)
	local state = cache[packet.scid]
	local plaintext, associated, nonce
	if state and state.version == packet.version then
		plaintext, associated, nonce = decrypt(data, packet, state)
	end
	if not plaintext and (not state or state.version ~= packet.version or state.dcid ~= packet.dcid) then
		-- Retry derives new Initial keys from the replacement DCID.
		state = keys(packet.version, packet.dcid)
		plaintext, associated, nonce = decrypt(data, packet, state)
		if plaintext then cache[packet.scid] = state end
	end
	if not plaintext then
		DLOG("quic: Initial authentication failed")
		return
	end
	local modified = reframe(plaintext)
	if not modified or modified == plaintext then return end
	local ciphertext, tag = aes_gcm(true, state.key, nonce, modified, associated)
	local payload = ciphertext .. tag
	local size = bitand(associated:byte(1), 3) + 1
	local mask = aes(true, state.hp, payload:sub(5 - size, 20 - size))
	local protected = string.char(bitxor(associated:byte(1), bitand(mask:byte(1), 0x0f)))
		.. associated:sub(2, #associated - size)
		.. bxor(associated:sub(-size), mask:sub(2, size + 1))
	DLOG("quic: reframed Initial")
	return protected .. payload
end

function quic(ctx, desync)
	if not desync.outgoing or not desync.dis.udp then return end
	local cache = {}
	if desync.track then
		cache = desync.track.lua_state[desync.func_instance] or cache
		desync.track.lua_state[desync.func_instance] = cache
	end
	local data = desync.dis.payload
	local output, changed = {}, false
	local position = 1
	while position <= #data do
		local packet = header(data, position)
		if not packet then
			output[#output + 1] = data:sub(position)
			break
		end
		local modified = packet.initial and rewrite(data, packet, cache)
		output[#output + 1] = modified or data:sub(position, packet.finish)
		changed = changed or not not modified
		position = packet.finish + 1
	end
	if changed then
		desync.dis.payload = table.concat(output)
		return VERDICT_MODIFY
	end
end
